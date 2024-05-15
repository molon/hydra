// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"log"
)

func (p *Persister) Authenticate(ctx context.Context, name, secret string) error {
	// TODO:
	log.Printf("Authenticate with %v %v", name, secret)
	return nil
	return p.r.Kratos().Authenticate(ctx, name, secret)
}
