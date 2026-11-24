package counter

import "testing"

func TestCount(t *testing.T) {
	if Count([]string{"a"}) != 1 {
		t.Fatal("wrong count")
	}
}
