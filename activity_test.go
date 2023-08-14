package txhelper

import (
	"testing"
)

func TestActivity(tester *testing.T) {
	if !privateCtestWrap() {
		tester.Errorf("invalid modular operations")
	}
}

// todo add benchmarks for activity computation
