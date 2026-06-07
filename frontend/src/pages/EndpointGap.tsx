import { Card, CodeBlock } from '@/components/Button'

// EndpointGap — the honest signpost. Several admin pages in the task
// list (projects, workspaces, identities, integrations, certificates)
// have NO backing endpoints on the canonical /v1/kms/* surface. This
// page surfaces that explicitly so operators don't think it's a UI
// regression — and so the next iteration of the backend has a checklist
// of what to add. One renderer; the route table parameterises the page.

export interface EndpointGapProps {
  title: string
  description: string
  endpoints: string[]
  rationale?: string
}

export function EndpointGap({ title, description, endpoints, rationale }: EndpointGapProps) {
  return (
    <div className="p-6">
      <header className="mb-4">
        <h1 className="text-lg font-semibold text-neutral-50">{title}</h1>
        <p className="text-[13px] text-neutral-400">{description}</p>
      </header>

      <Card className="p-5">
        <h2 className="mb-2 text-sm font-semibold text-amber-300">No backing endpoints</h2>
        <p className="text-[12px] text-neutral-400">
          The canonical KMS surface (HIP-0027) does not expose a {title.toLowerCase()} resource. This
          page is a stub so operators can find the documentation; the backend will need to add the
          routes below before the UI can render real data.
        </p>
        <div className="mt-3 flex flex-col gap-2">
          {endpoints.map((e) => (
            <CodeBlock key={e}>{e}</CodeBlock>
          ))}
        </div>
        {rationale && <p className="mt-3 text-[12px] text-neutral-400">{rationale}</p>}
      </Card>
    </div>
  )
}
