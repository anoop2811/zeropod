package e2e

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

const runtimeClassName = "zeropod"

func TestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test")
	}

	_, client, port := setup(t)
	ctx := context.Background()

	cases := map[string]struct {
		pod              *corev1.Pod
		parallelRequests int
	}{
		"without pre-dump": {
			pod:              testPod(false, 0),
			parallelRequests: 1,
		},
		"parallel requests": {
			pod:              testPod(false, 0),
			parallelRequests: 4,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			svc := testService()

			cleanupPod := createPodAndWait(t, ctx, client, tc.pod)
			cleanupService := createServiceAndWait(t, ctx, client, svc, 1)
			defer cleanupPod()
			defer cleanupService()

			wg := sync.WaitGroup{}
			for i := 0; i < tc.parallelRequests; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					before := time.Now()
					resp, err := http.Get(fmt.Sprintf("http://localhost:%d", port))
					if err != nil {
						t.Error(err)
						return
					}
					t.Logf("request took %s", time.Since(before))
					assert.Equal(t, resp.StatusCode, http.StatusOK)
				}()
			}
			wg.Wait()
		})
	}
}
