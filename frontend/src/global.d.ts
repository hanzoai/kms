/// <reference types="vite/client" />

// @hanzo/brand v1.3.0 ships JS without typings. We only need the runtime
// brand config (brand.name, brand.title, etc.), so we declare a narrow
// shape rather than `any`. When @hanzo/brand publishes typings we can
// drop this and pick them up automatically.
declare module '@hanzo/brand' {
  export interface HanzoBrandConfig {
    name: string
    title: string
    shortName: string
    appDomain: string
    docsDomain: string
    [key: string]: unknown
  }
  export const brand: HanzoBrandConfig
}
