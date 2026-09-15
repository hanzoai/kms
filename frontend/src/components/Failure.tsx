import { ApiError } from '@/lib/api'
import { signIn } from '@/lib/session'
import { Button, Notice } from '@/components/ui'

/** A refusal, with the way back in when the session is what failed. */
export function Failure({ error }: { error: Error }) {
  const signedOut = error instanceof ApiError && (error.status === 401 || /authentication required/i.test(error.message))
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Notice>{signedOut ? 'Your session has ended.' : error.message}</Notice>
      {signedOut && (
        <Button variant="secondary" onClick={() => void signIn()}>
          Sign in again
        </Button>
      )}
    </div>
  )
}
