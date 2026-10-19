package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCheckPageOrdinals(t *testing.T) {
	page := func(ords ...int64) []Record {
		var out []Record
		for _, o := range ords {
			out = append(out, Record{Ord: o})
		}
		return out
	}
	for name, tc := range map[string]struct {
		page  []Record
		after int64
		ok    bool
	}{
		"empty":                 {page(), 7, true},
		"contiguous from zero":  {page(1, 2, 3), 0, true},
		"contiguous after":      {page(11, 12), 10, true},
		"gap in the middle":     {page(11, 13, 14), 10, false},
		"duplicate":             {page(11, 11), 10, false},
		"starts late":           {page(12, 13), 10, false},
		"ordinals not filled":   {[]Record{{}}, 0, false},
		"deleted row, same len": {page(11, 12, 14), 10, false},
	} {
		err := CheckPageOrdinals(tc.page, tc.after)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrOrdinalGap)) {
			t.Errorf("%s: err %v, want ok=%v", name, err, tc.ok)
		}
	}
}

// TestMemRecordsAfterFillsOrdinals: RecordsAfter returns the ordinals CheckPageOrdinals expects.
func TestMemRecordsAfterFillsOrdinals(t *testing.T) {
	m := NewMem()
	for i := 0; i < 5; i++ {
		if _, _, err := m.PutRecord("p", string(rune('a'+i)), Record{JSON: "{}", ContentHash: "sha256:" + string(rune('a'+i)), SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := m.RecordsAfter("p", 2, 10)
	if err != nil || len(page) != 3 || CheckPageOrdinals(page, 2) != nil || page[0].Ord != 3 {
		t.Fatalf("page %+v err %v", page, err)
	}
}

func TestMemWithBudgetReportsALateFn(t *testing.T) {
	m := NewMem()
	if err := m.WithBudget(time.Hour, func(Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
	err := m.WithBudget(5*time.Millisecond, func(Store) error { time.Sleep(30 * time.Millisecond); return nil })
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("err %v, want ErrBudgetExceeded", err)
	}
	boom := errors.New("boom")
	if err := m.WithBudget(time.Hour, func(Store) error { return boom }); err != boom {
		t.Fatalf("err %v, want the fn error unchanged", err)
	}
}

// TestPostgresWithBudgetCancelsAStatementAndKeepsTheTransaction: a statement over the budget is cancelled and
// reported as ErrBudgetExceeded, and the project transaction still works afterwards (it can read and commit); the
// statement timeout is restored for later statements.
func TestPostgresWithBudgetCancelsAStatementAndKeepsTheTransaction(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	err := p.WithProjectWrite(context.Background(), "p", func(st Store) error {
		b := st.(*Postgres)
		budgetErr := st.WithBudget(100*time.Millisecond, func(in Store) error {
			_, e := in.(*Postgres).queries().Exec(b.callContext(), `SELECT pg_sleep(5)`)
			return e
		})
		if !errors.Is(budgetErr, ErrBudgetExceeded) {
			t.Fatalf("budget error %v, want ErrBudgetExceeded", budgetErr)
		}
		var timeout string
		if e := b.queries().QueryRow(b.callContext(), `SELECT current_setting('statement_timeout')`).Scan(&timeout); e != nil {
			t.Fatalf("the transaction is unusable after a budget timeout: %v", e)
		}
		if timeout == "100ms" {
			t.Fatalf("statement_timeout stayed at the budget")
		}
		if e := st.WithBudget(time.Minute, func(in Store) error { _, e := in.RecordCount("p"); return e }); e != nil {
			t.Fatalf("a budgeted read inside the same transaction: %v", e)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("the transaction must still commit: %v", err)
	}
}

// TestPostgresWithBudgetCoversTheWholeFunction: the budget is a deadline for all of fn, not an allowance per
// statement. Two 400 ms statements fit one by one inside a 600 ms budget, but together they do not: the second is
// cancelled with the time that remains, and a statement that starts after the deadline is not sent at all.
func TestPostgresWithBudgetCoversTheWholeFunction(t *testing.T) {
	p, done := newTestStore(t)
	defer done()
	err := p.WithProjectWrite(context.Background(), "p", func(st Store) error {
		b := st.(*Postgres)
		start := time.Now()
		budgetErr := st.WithBudget(600*time.Millisecond, func(in Store) error {
			q := in.(*Postgres).queries()
			if _, e := q.Exec(b.callContext(), `SELECT pg_sleep(0.4)`); e != nil {
				return e
			}
			_, e := q.Exec(b.callContext(), `SELECT pg_sleep(0.4)`)
			return e
		})
		if !errors.Is(budgetErr, ErrBudgetExceeded) {
			t.Fatalf("two statements of 400 ms under a 600 ms budget: %v, want ErrBudgetExceeded", budgetErr)
		}
		if took := time.Since(start); took > 700*time.Millisecond {
			t.Fatalf("the budget let fn run %s, want about 600 ms (the second statement must be cut short)", took)
		}
		late := st.WithBudget(50*time.Millisecond, func(in Store) error {
			time.Sleep(80 * time.Millisecond)
			_, e := in.(*Postgres).queries().Exec(b.callContext(), `SELECT 1`)
			return e
		})
		if !errors.Is(late, ErrBudgetExceeded) {
			t.Fatalf("a statement after the deadline: %v, want ErrBudgetExceeded", late)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("the transaction must still commit: %v", err)
	}
}
