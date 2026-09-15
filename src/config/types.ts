export type ReviewerConfig = {
  provider?: string
  model?: string
  inheritParent?: boolean
}

export type SecurityGuidanceConfig = {
  enabled: boolean
  patterns: boolean
  stopReview: boolean
  commitReview: boolean
  pushReview: boolean
  reviewer: ReviewerConfig
  debug: boolean
}

export const DEFAULT_CONFIG: SecurityGuidanceConfig = {
  enabled: true,
  patterns: true,
  stopReview: true,
  commitReview: true,
  pushReview: true,
  reviewer: { inheritParent: false },
  debug: false,
}
