package sync

import "testing"

func TestThreeWay(t *testing.T) {
	cases := []struct {
		b, l, r string
		remove  bool
		want    Action
	}{{"a", "a", "a", false, Clean}, {"a", "b", "a", false, Upload}, {"a", "a", "b", false, Download}, {"a", "b", "b", false, Clean}, {"a", "b", "c", false, Conflict}, {"a", "", "a", false, Missing}, {"a", "", "b", false, Download}, {"", "a", "", false, Upload}, {"", "a", "b", false, Conflict}, {"", "", "b", false, Download}, {"a", "a", Deleted, false, DeletePending}, {"a", "b", Deleted, false, Conflict}, {Deleted, "b", Deleted, false, Upload}, {"a", "a", "a", true, Tombstone}, {"a", "a", "b", true, Conflict}, {"a", "", Deleted, false, Clean}}
	for _, c := range cases {
		if got := Decide(c.b, c.l, c.r, c.remove); got != c.want {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}
func FuzzPlanner(f *testing.F) {
	f.Add("a", "b", "c", false)
	f.Fuzz(func(t *testing.T, b, l, r string, remove bool) {
		action := Decide(b, l, r, remove)
		if l == "" && action == Upload {
			t.Fatal("implicit upload of absence")
		}
		if !remove && action == Tombstone {
			t.Fatal("implicit deletion")
		}
		if action != Decide(b, l, r, remove) {
			t.Fatal("nondeterminism")
		}
	})
}
