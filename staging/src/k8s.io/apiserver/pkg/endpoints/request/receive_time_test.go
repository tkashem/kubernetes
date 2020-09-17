package request

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestWithRequestReceiveTime(t *testing.T) {
	tests := []struct{
		name                string
		receiveTimeExpected time.Time
		okExpected          bool

	} {
		{
			name:                "time is not empty",
			receiveTimeExpected: time.Now(),
			okExpected:          true,
		},
		{
			name:                "time is empty",
			receiveTimeExpected: time.Time{},
			okExpected:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := context.TODO()
			ctxGot := WithReceiveTime(parent, test.receiveTimeExpected)
			if ctxGot == nil {
				t.Fatal("WithReceiveTime: expected a non nil context, got nil")
			}

			receiveTimeGot, okGot :=  ReceiveTimeFrom(ctxGot)
			if test.okExpected != okGot {
				t.Errorf("ReceiveTimeFrom: expected=%s got=%s", strconv.FormatBool(test.okExpected), strconv.FormatBool(okGot))
			}

			if test.receiveTimeExpected != receiveTimeGot {
				t.Errorf("ReceiveTimeFrom: expected received time=%s but got=%s", test.receiveTimeExpected, receiveTimeGot)
			}
		})
	}
}
