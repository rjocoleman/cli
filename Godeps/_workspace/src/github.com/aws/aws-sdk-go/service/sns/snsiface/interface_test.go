// THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT.

package snsiface_test

import (
	"testing"

	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/sns"
	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/stretchr/testify/assert"
)

func TestInterface(t *testing.T) {
	assert.Implements(t, (*snsiface.SNSAPI)(nil), sns.New(nil))
}