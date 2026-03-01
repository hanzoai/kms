// MIT License
// Copyright (c) 2024 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT
//
// Re-export TPermissionServiceFactory so that fastify.d.ts and other consumers
// can import from a stable path without depending directly on permission-service.ts.

export type { TPermissionServiceFactory } from "./permission-service";
