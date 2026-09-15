import os from "node:os"
import path from "node:path"

export function configRoot(): string {
  return process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
}

export function stateRoot(): string {
  return process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state")
}

export function securityConfigDir(): string {
  return path.join(configRoot(), "opencode", "security-guidance")
}

export function securityStateDir(): string {
  return path.join(stateRoot(), "opencode", "security-guidance")
}

export function securityLogDir(): string {
  return path.join(securityStateDir(), "logs")
}
