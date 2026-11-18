package server

import "context"

type convIDKey struct{}

func withConvID(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, convIDKey{}, id)
}

func convIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(convIDKey{}).(int64)
	return v
}
