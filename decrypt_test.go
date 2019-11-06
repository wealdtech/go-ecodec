// Copyright © 2019 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecodec_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wealdtech/go-ecodec"
)

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name          string
		encryptedData []byte
		key           []byte
		data          []byte
		err           error
	}{
		{
			name:          "DataShort",
			encryptedData: _byteArray("01"),
			key:           _byteArray("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"),
			err:           errors.New("encrypted data must be at least 81 bytes"),
		},
		{
			name:          "VersionIncorrect",
			encryptedData: _byteArray("02aa78ce19c2662681376386e06695ead4f25678c2ca07923746a595147bab16357b7040432a9b723f6c8f34f94b5ea718df37285e97320460b15cbdbee1bb9ef57bd298f7fc2bd6cda9200d75fd4d3f69923cb8d3434def57b3077ab75150572cc53b4d39ff1c95fb9aa5955602e36bba"),
			key:           _byteArray("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"),
			err:           errors.New("unhandled version 0x02"),
		},
		{
			name:          "KeyInvalid",
			encryptedData: _byteArray("01aa78ce19c2662681376386e06695ead4f25678c2ca07923746a595147bab16357b7040432a9b723f6c8f34f94b5ea718df37285e97320460b15cbdbee1bb9ef57bd298f7fc2bd6cda9200d75fd4d3f69923cb8d3434def57b3077ab75150572cc53b4d39ff1c95fb9aa5955602e36bba"),
			key:           _byteArray("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f11"),
			err:           errors.New("invalid key"),
		},
		{
			name:          "Good1",
			encryptedData: _byteArray("01aa78ce19c2662681376386e06695ead4f25678c2ca07923746a595147bab16357b7040432a9b723f6c8f34f94b5ea718df37285e97320460b15cbdbee1bb9ef57bd298f7fc2bd6cda9200d75fd4d3f69923cb8d3434def57b3077ab75150572cc53b4d39ff1c95fb9aa5955602e36bba"),
			key:           _byteArray("0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"),
			data:          _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := ecodec.Decrypt(test.encryptedData, test.key)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.data, data)
			}
		})
	}
}
