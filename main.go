package main

import (
	"github.com/ctrox/zeropod/runc"
	v2 "github.com/ctrox/zeropod/runc/v2"

	"github.com/containerd/containerd/runtime/v2/shim"
)

func shimConfig(config *shim.Config) {
	// config.NoReaper = true
	// config.NoSubreaper = true
}

func main() {
	shim.Run(runc.RuntimeName, v2.New, shimConfig)
}
