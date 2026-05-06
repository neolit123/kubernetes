/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package attestation contains controllers that garbage-collect attestation
// API objects: expired challenges, pending-but-expired enrollments, and
// NodeAttestationDocuments that have aged past the retention window.
package attestation

import (
	"context"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
)

const (
	// DefaultDocumentRetentionWindow is the default period after which a
	// NodeAttestationDocument is deleted for audit-log retention purposes.
	DefaultDocumentRetentionWindow = 24 * time.Hour

	// challengeQueueName is used for workqueue metrics.
	challengeQueueName = "attestation_challenge_cleaner"
	// enrollmentQueueName is used for workqueue metrics.
	enrollmentQueueName = "attestation_enrollment_cleaner"
	// documentQueueName is used for workqueue metrics.
	documentQueueName = "attestation_document_cleaner"
)

// AttestationCleaner is a controller that periodically reaps stale attestation
// objects:
//
//  1. NodeAttestationChallenges whose Status.ExpiresAt is in the past.
//  2. NodeIdentityEnrollments that are still Pending after Spec.BootstrapExpiry.
//  3. NodeAttestationDocuments older than the configured retentionWindow.
//
// It uses a polling model (re-list every resyncPeriod) for alpha simplicity
// rather than a full event-driven informer cache.
type AttestationCleaner struct {
	client          clientset.Interface
	resyncPeriod    time.Duration
	retentionWindow time.Duration

	// challengeQueue, enrollmentQueue, documentQueue decouple the list pass
	// from the individual Delete/Update calls so we get rate-limiting for free.
	challengeQueue  workqueue.TypedRateLimitingInterface[string]
	enrollmentQueue workqueue.TypedRateLimitingInterface[string]
	documentQueue   workqueue.TypedRateLimitingInterface[string]
}

// NewAttestationCleaner constructs an AttestationCleaner with the given client
// and resync period.  Document retention defaults to DefaultDocumentRetentionWindow.
func NewAttestationCleaner(client clientset.Interface, resyncPeriod time.Duration) *AttestationCleaner {
	return &AttestationCleaner{
		client:          client,
		resyncPeriod:    resyncPeriod,
		retentionWindow: DefaultDocumentRetentionWindow,
		challengeQueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: challengeQueueName},
		),
		enrollmentQueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: enrollmentQueueName},
		),
		documentQueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: documentQueueName},
		),
	}
}

// WithRetentionWindow overrides the document retention window.
func (ac *AttestationCleaner) WithRetentionWindow(d time.Duration) *AttestationCleaner {
	ac.retentionWindow = d
	return ac
}

// Run starts the three cleanup loops and blocks until ctx is cancelled.
// workers is the number of parallel workers per queue.
func (ac *AttestationCleaner) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	logger := klog.FromContext(ctx)
	logger.Info("Starting attestation cleaner controller")

	var wg sync.WaitGroup
	defer func() {
		logger.Info("Shutting down attestation cleaner controller")
		ac.challengeQueue.ShutDown()
		ac.enrollmentQueue.ShutDown()
		ac.documentQueue.ShutDown()
		wg.Wait()
	}()

	// Periodic list passes that populate the queues.
	wg.Go(func() { wait.UntilWithContext(ctx, ac.syncChallenges, ac.resyncPeriod) })
	wg.Go(func() { wait.UntilWithContext(ctx, ac.syncEnrollments, ac.resyncPeriod) })
	wg.Go(func() { wait.UntilWithContext(ctx, ac.syncDocuments, ac.resyncPeriod) })

	// Worker goroutines that drain the queues.
	for i := 0; i < workers; i++ {
		wg.Go(func() { wait.UntilWithContext(ctx, ac.runChallengeWorker, time.Second) })
		wg.Go(func() { wait.UntilWithContext(ctx, ac.runEnrollmentWorker, time.Second) })
		wg.Go(func() { wait.UntilWithContext(ctx, ac.runDocumentWorker, time.Second) })
	}

	<-ctx.Done()
}

// ---------------------------------------------------------------------------
// Challenge cleanup (delete when ExpiresAt is past)
// ---------------------------------------------------------------------------

func (ac *AttestationCleaner) syncChallenges(ctx context.Context) {
	logger := klog.FromContext(ctx)
	list, err := ac.client.AttestationV1alpha1().NodeAttestationChallenges().List(ctx, metav1.ListOptions{})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("attestationcleaner: listing challenges: %w", err))
		return
	}
	now := time.Now()
	for _, ch := range list.Items {
		if !ch.Status.ExpiresAt.IsZero() && now.After(ch.Status.ExpiresAt.Time) {
			logger.V(4).Info("Queuing expired challenge for deletion", "challenge", ch.Name)
			ac.challengeQueue.Add(ch.Name)
		}
	}
}

func (ac *AttestationCleaner) runChallengeWorker(ctx context.Context) {
	for ac.processNextChallenge(ctx) {
	}
}

func (ac *AttestationCleaner) processNextChallenge(ctx context.Context) bool {
	key, quit := ac.challengeQueue.Get()
	if quit {
		return false
	}
	defer ac.challengeQueue.Done(key)

	if err := ac.deleteExpiredChallenge(ctx, key); err != nil {
		ac.challengeQueue.AddRateLimited(key)
		utilruntime.HandleError(fmt.Errorf("attestationcleaner: deleting challenge %q: %w", key, err))
		return true
	}
	ac.challengeQueue.Forget(key)
	return true
}

func (ac *AttestationCleaner) deleteExpiredChallenge(ctx context.Context, name string) error {
	logger := klog.FromContext(ctx)

	ch, err := ac.client.AttestationV1alpha1().NodeAttestationChallenges().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil // already gone
	}
	if err != nil {
		return err
	}

	// Re-check expiry after the GET to avoid a TOCTOU window.
	if ch.Status.ExpiresAt.IsZero() || !time.Now().After(ch.Status.ExpiresAt.Time) {
		return nil // not expired yet
	}

	opts := metav1.DeleteOptions{}
	if uid := ch.UID; uid != "" {
		opts.Preconditions = &metav1.Preconditions{UID: &uid}
	}
	err = ac.client.AttestationV1alpha1().NodeAttestationChallenges().Delete(ctx, name, opts)
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil // already gone or UID precondition failed (object recreated)
	}
	if err != nil {
		return err
	}
	logger.V(3).Info("Deleted expired NodeAttestationChallenge", "challenge", name,
		"expiredAt", ch.Status.ExpiresAt.Time)
	return nil
}

// ---------------------------------------------------------------------------
// Enrollment expiry (Pending → Expired when BootstrapExpiry has passed)
// ---------------------------------------------------------------------------

func (ac *AttestationCleaner) syncEnrollments(ctx context.Context) {
	logger := klog.FromContext(ctx)
	list, err := ac.client.AttestationV1alpha1().NodeIdentityEnrollments().List(ctx, metav1.ListOptions{})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("attestationcleaner: listing enrollments: %w", err))
		return
	}
	now := time.Now()
	for _, enr := range list.Items {
		if enr.Status.Phase == attestationv1alpha1.EnrollmentPhasePending &&
			enr.Spec.BootstrapExpiry != nil &&
			now.After(enr.Spec.BootstrapExpiry.Time) {
			logger.V(4).Info("Queuing expired enrollment for phase transition", "enrollment", enr.Name)
			ac.enrollmentQueue.Add(enr.Name)
		}
	}
}

func (ac *AttestationCleaner) runEnrollmentWorker(ctx context.Context) {
	for ac.processNextEnrollment(ctx) {
	}
}

func (ac *AttestationCleaner) processNextEnrollment(ctx context.Context) bool {
	key, quit := ac.enrollmentQueue.Get()
	if quit {
		return false
	}
	defer ac.enrollmentQueue.Done(key)

	if err := ac.expireEnrollment(ctx, key); err != nil {
		ac.enrollmentQueue.AddRateLimited(key)
		utilruntime.HandleError(fmt.Errorf("attestationcleaner: expiring enrollment %q: %w", key, err))
		return true
	}
	ac.enrollmentQueue.Forget(key)
	return true
}

func (ac *AttestationCleaner) expireEnrollment(ctx context.Context, name string) error {
	logger := klog.FromContext(ctx)

	enr, err := ac.client.AttestationV1alpha1().NodeIdentityEnrollments().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// Only act on Pending enrollments whose deadline has actually passed.
	if enr.Status.Phase != attestationv1alpha1.EnrollmentPhasePending {
		return nil // already transitioned by someone else
	}
	if enr.Spec.BootstrapExpiry == nil || !time.Now().After(enr.Spec.BootstrapExpiry.Time) {
		return nil // not yet expired
	}

	updated := enr.DeepCopy()
	updated.Status.Phase = attestationv1alpha1.EnrollmentPhaseExpired

	_, err = ac.client.AttestationV1alpha1().NodeIdentityEnrollments().UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		// Concurrent update; re-enqueue so we can retry with a fresh get.
		return fmt.Errorf("conflict updating enrollment %q status: %w", name, err)
	}
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	logger.V(3).Info("Transitioned NodeIdentityEnrollment to Expired",
		"enrollment", name, "bootstrapExpiry", enr.Spec.BootstrapExpiry.Time)
	return nil
}

// ---------------------------------------------------------------------------
// Document retention (delete documents older than retentionWindow)
// ---------------------------------------------------------------------------

func (ac *AttestationCleaner) syncDocuments(ctx context.Context) {
	logger := klog.FromContext(ctx)
	list, err := ac.client.AttestationV1alpha1().NodeAttestationDocuments().List(ctx, metav1.ListOptions{})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("attestationcleaner: listing documents: %w", err))
		return
	}
	cutoff := time.Now().Add(-ac.retentionWindow)
	for _, doc := range list.Items {
		if doc.CreationTimestamp.Before(&metav1.Time{Time: cutoff}) {
			logger.V(4).Info("Queuing old document for deletion", "document", doc.Name,
				"createdAt", doc.CreationTimestamp.Time)
			ac.documentQueue.Add(doc.Name)
		}
	}
}

func (ac *AttestationCleaner) runDocumentWorker(ctx context.Context) {
	for ac.processNextDocument(ctx) {
	}
}

func (ac *AttestationCleaner) processNextDocument(ctx context.Context) bool {
	key, quit := ac.documentQueue.Get()
	if quit {
		return false
	}
	defer ac.documentQueue.Done(key)

	if err := ac.deleteOldDocument(ctx, key); err != nil {
		ac.documentQueue.AddRateLimited(key)
		utilruntime.HandleError(fmt.Errorf("attestationcleaner: deleting document %q: %w", key, err))
		return true
	}
	ac.documentQueue.Forget(key)
	return true
}

func (ac *AttestationCleaner) deleteOldDocument(ctx context.Context, name string) error {
	logger := klog.FromContext(ctx)

	doc, err := ac.client.AttestationV1alpha1().NodeAttestationDocuments().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-ac.retentionWindow)
	if !doc.CreationTimestamp.Before(&metav1.Time{Time: cutoff}) {
		return nil // not old enough yet
	}

	opts := metav1.DeleteOptions{}
	if uid := doc.UID; uid != "" {
		opts.Preconditions = &metav1.Preconditions{UID: &uid}
	}
	err = ac.client.AttestationV1alpha1().NodeAttestationDocuments().Delete(ctx, name, opts)
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	if err != nil {
		return err
	}
	logger.V(3).Info("Deleted old NodeAttestationDocument", "document", name,
		"createdAt", doc.CreationTimestamp.Time, "retentionWindow", ac.retentionWindow)
	return nil
}
