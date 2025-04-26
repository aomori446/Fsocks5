package main

import (
	"context"
	"log/slog"
)

func logger() {
	slog.Info("ss")
	slog.Error("sss")
	slog.Log(context.TODO(), slog.LevelInfo, "sss")
	slog.Default().With()
	slog.Default().WithGroup("group name")
}
