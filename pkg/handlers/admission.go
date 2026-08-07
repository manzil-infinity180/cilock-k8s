// Package handlers implements the validating admission webhook endpoint.
package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/manzil-infinity180/cilock-k8s/pkg/platform"
	"github.com/manzil-infinity180/cilock-k8s/pkg/verify"
)

// Admission returns an http.HandlerFunc that validates every container image
// in an incoming Pod against the witness policy.
//
// pc is optional. Without it (nil) the webhook behaves exactly like the
// original PoC: always enforcing, reporting nothing. With it, the enforcement
// mode comes from the platform's last check-in (AUDIT admits everything but
// records the would-deny) and every per-container verdict is queued for the
// batched decision report.
func Admission(verifier *verify.Verifier, pc *platform.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
			return
		}

		review := admv1.AdmissionReview{}
		if err := json.Unmarshal(body, &review); err != nil {
			http.Error(w, fmt.Sprintf("failed to parse admission review: %v", err), http.StatusBadRequest)
			return
		}

		if review.Request == nil {
			http.Error(w, "admission review contained no request", http.StatusBadRequest)
			return
		}

		response := &admv1.AdmissionResponse{UID: review.Request.UID}
		review.Response = response

		pod := &corev1.Pod{}
		if err := json.Unmarshal(review.Request.Object.Raw, pod); err != nil {
			deny(response, fmt.Sprintf("failed to parse pod: %v", err))
			writeReview(w, &review)
			return
		}

		podName := pod.Name
		if podName == "" {
			podName = pod.GenerateName + "?"
		}

		mode := platform.ModeEnforce
		if pc != nil {
			mode = pc.Mode()
		}

		// DISABLED: the platform told the agent to stand down entirely — no
		// verification, no recording, admit as if the webhook were absent.
		if mode == platform.ModeDisabled {
			response.Allowed = true
			response.Result = &metav1.Status{Code: http.StatusOK, Message: "admission control disabled by platform"}
			writeReview(w, &review)
			return
		}

		workloadKind, workloadName := ownerWorkload(pod)

		containers := append([]corev1.Container{}, pod.Spec.InitContainers...)
		containers = append(containers, pod.Spec.Containers...)

		type containerVerdict struct {
			container corev1.Container
			decision  platform.Decision
		}

		verified := []string{}
		failures := []string{}
		verdicts := make([]containerVerdict, 0, len(containers))
		for _, container := range containers {
			d := platform.Decision{
				Namespace:    pod.Namespace,
				WorkloadKind: workloadKind,
				WorkloadName: workloadName,
				ImageRef:     container.Image,
				Mode:         mode,
				At:           time.Now().UTC(),
			}

			result, err := verifier.VerifyImage(r.Context(), container.Image)
			if err != nil {
				d.Verdict = platform.VerdictFail
				d.Reason = err.Error()
				failures = append(failures, fmt.Sprintf("container %q image %q: %v", container.Name, container.Image, err))
			} else {
				d.Verdict = platform.VerdictPass
				d.ImageDigest = result.Digests.ManifestDigest
				d.ImageID = result.Digests.ConfigDigest
				log.Printf("PASS pod=%s/%s container=%s image=%s digests=(%s) steps=%v",
					pod.Namespace, podName, container.Name, container.Image, result.Digests, result.StepNames)
				verified = append(verified, container.Image)
			}

			verdicts = append(verdicts, containerVerdict{container: container, decision: d})
		}

		// The pod is denied only when something failed AND we are enforcing.
		// In AUDIT mode a failure is recorded as verdict=FAIL, action=ADMITTED.
		denied := len(failures) > 0 && mode == platform.ModeEnforce

		action := platform.ActionAdmitted
		if denied {
			action = platform.ActionDenied
		}
		for _, cv := range verdicts {
			cv.decision.Action = action
			if cv.decision.Verdict == platform.VerdictFail {
				verb := "DENY"
				if !denied {
					verb = "WOULD-DENY (audit)"
				}
				log.Printf("%s pod=%s/%s container=%s image=%s: %s", verb, pod.Namespace, podName, cv.container.Name, cv.container.Image, cv.decision.Reason)
			}
			if pc != nil {
				pc.Record(cv.decision)
			}
		}

		if denied {
			deny(response, fmt.Sprintf("witness policy verification failed: %s", strings.Join(failures, "; ")))
			writeReview(w, &review)
			return
		}

		response.Allowed = true
		message := fmt.Sprintf("witness policy verification passed for images: %s", strings.Join(verified, ", "))
		if len(failures) > 0 {
			message = fmt.Sprintf("audit mode: policy failed but pod admitted: %s", strings.Join(failures, "; "))
		}
		response.Result = &metav1.Status{
			Code:    http.StatusOK,
			Message: message,
		}

		writeReview(w, &review)
	}
}

// ownerWorkload names the workload that owns the pod, from its first owner
// reference (ReplicaSet, StatefulSet, Job, ...). Empty for bare pods; the
// platform records the decision without a workload in that case.
func ownerWorkload(pod *corev1.Pod) (kind, name string) {
	if len(pod.OwnerReferences) == 0 {
		return "", ""
	}
	owner := pod.OwnerReferences[0]
	return owner.Kind, owner.Name
}

func deny(response *admv1.AdmissionResponse, message string) {
	response.Allowed = false
	response.Result = &metav1.Status{
		Code:    http.StatusForbidden,
		Message: message,
	}
}

func writeReview(w http.ResponseWriter, review *admv1.AdmissionReview) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		log.Printf("failed to write admission response: %v", err)
	}
}

// Health is a trivial readiness endpoint.
func Health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
