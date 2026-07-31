// Package handlers implements the validating admission webhook endpoint.
package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/manzil-infinity180/cilock-k8s/pkg/verify"
)

// Admission returns an http.HandlerFunc that validates every container image
// in an incoming Pod against the witness policy.
func Admission(verifier *verify.Verifier) http.HandlerFunc {
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

		containers := append([]corev1.Container{}, pod.Spec.InitContainers...)
		containers = append(containers, pod.Spec.Containers...)

		verified := []string{}
		failures := []string{}
		for _, container := range containers {
			result, err := verifier.VerifyImage(r.Context(), container.Image)
			if err != nil {
				log.Printf("DENY pod=%s/%s container=%s image=%s: %v", pod.Namespace, podName, container.Name, container.Image, err)
				failures = append(failures, fmt.Sprintf("container %q image %q: %v", container.Name, container.Image, err))
				continue
			}

			log.Printf("PASS pod=%s/%s container=%s image=%s digests=(%s) steps=%v",
				pod.Namespace, podName, container.Name, container.Image, result.Digests, result.StepNames)
			verified = append(verified, container.Image)
		}

		if len(failures) > 0 {
			deny(response, fmt.Sprintf("witness policy verification failed: %s", strings.Join(failures, "; ")))
			writeReview(w, &review)
			return
		}

		response.Allowed = true
		response.Result = &metav1.Status{
			Code:    http.StatusOK,
			Message: fmt.Sprintf("witness policy verification passed for images: %s", strings.Join(verified, ", ")),
		}

		writeReview(w, &review)
	}
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
