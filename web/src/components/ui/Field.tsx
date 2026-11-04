import {
  forwardRef,
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react'
import { cn } from '@/lib/cn'

interface FieldShellProps {
  label: string
  hint?: ReactNode
  error?: string | null
  required?: boolean
  htmlFor?: string
  className?: string
  children: ReactNode
}

export function FieldShell({
  label,
  hint,
  error,
  required,
  htmlFor,
  className,
  children,
}: FieldShellProps) {
  return (
    <div className={cn('min-w-0', className)}>
      <label className="field-label" htmlFor={htmlFor}>
        {label}
        {required && (
          <span className="ml-1 text-crit" aria-hidden="true">
            *
          </span>
        )}
      </label>
      {children}
      {error ? (
        <p className="mt-1 text-xs text-crit">{error}</p>
      ) : hint ? (
        <p className="mt-1 text-xs text-faint">{hint}</p>
      ) : null}
    </div>
  )
}

export interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  hint?: ReactNode
  error?: string | null
  wrapperClassName?: string
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(function TextField(
  { label, hint, error, className, wrapperClassName, required, ...rest },
  ref,
) {
  const autoId = useId()
  const id = rest.id ?? autoId
  return (
    <FieldShell
      label={label}
      hint={hint}
      error={error}
      required={required}
      htmlFor={id}
      className={wrapperClassName}
    >
      <input
        ref={ref}
        id={id}
        required={required}
        aria-invalid={error ? true : undefined}
        className={cn('input-base', error && 'border-crit', className)}
        {...rest}
      />
    </FieldShell>
  )
})

export interface SelectFieldProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string
  hint?: ReactNode
  error?: string | null
  wrapperClassName?: string
  children: ReactNode
}

export const SelectField = forwardRef<HTMLSelectElement, SelectFieldProps>(
  function SelectField(
    { label, hint, error, className, wrapperClassName, required, children, ...rest },
    ref,
  ) {
    const autoId = useId()
    const id = rest.id ?? autoId
    return (
      <FieldShell
        label={label}
        hint={hint}
        error={error}
        required={required}
        htmlFor={id}
        className={wrapperClassName}
      >
        <select
          ref={ref}
          id={id}
          required={required}
          className={cn('input-base appearance-none pr-8', error && 'border-crit', className)}
          style={{
            backgroundImage:
              "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12' fill='%23888'><path d='M2.5 4.5 6 8l3.5-3.5z'/></svg>\")",
            backgroundRepeat: 'no-repeat',
            backgroundPosition: 'right 8px center',
          }}
          {...rest}
        >
          {children}
        </select>
      </FieldShell>
    )
  },
)

export interface TextAreaFieldProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string
  hint?: ReactNode
  error?: string | null
  wrapperClassName?: string
}

export const TextAreaField = forwardRef<HTMLTextAreaElement, TextAreaFieldProps>(
  function TextAreaField(
    { label, hint, error, className, wrapperClassName, required, ...rest },
    ref,
  ) {
    const autoId = useId()
    const id = rest.id ?? autoId
    return (
      <FieldShell
        label={label}
        hint={hint}
        error={error}
        required={required}
        htmlFor={id}
        className={wrapperClassName}
      >
        <textarea
          ref={ref}
          id={id}
          required={required}
          className={cn('input-base resize-y', error && 'border-crit', className)}
          {...rest}
        />
      </FieldShell>
    )
  },
)

export function Checkbox({
  label,
  hint,
  className,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode; hint?: ReactNode }) {
  const autoId = useId()
  const id = rest.id ?? autoId
  return (
    <div className={cn('flex items-start gap-2.5', className)}>
      <input
        id={id}
        type="checkbox"
        className="mt-0.5 h-4 w-4 shrink-0 cursor-pointer rounded border-border-strong bg-elevated accent-[rgb(var(--c-accent))]"
        {...rest}
      />
      <div className="min-w-0">
        <label htmlFor={id} className="cursor-pointer select-none text-sm text-fg">
          {label}
        </label>
        {hint && <p className="text-xs text-faint">{hint}</p>}
      </div>
    </div>
  )
}

/** Switch-style boolean, used where the setting has consequences. */
export function Toggle({
  checked,
  onChange,
  label,
  hint,
  danger,
  disabled,
  id: idProp,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  label: ReactNode
  hint?: ReactNode
  danger?: boolean
  disabled?: boolean
  id?: string
}) {
  const autoId = useId()
  const id = idProp ?? autoId
  return (
    <div className="flex items-start gap-3">
      <button
        type="button"
        id={id}
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative mt-0.5 h-5 w-9 shrink-0 rounded-full border transition-colors',
          checked
            ? danger
              ? 'border-crit bg-crit'
              : 'border-accent bg-accent'
            : 'border-border-strong bg-elevated',
        )}
      >
        <span
          className={cn(
            'absolute top-0.5 h-3.5 w-3.5 rounded-full bg-white transition-transform',
            checked ? 'translate-x-[18px]' : 'translate-x-0.5',
          )}
        />
      </button>
      <div className="min-w-0">
        <label htmlFor={id} className="cursor-pointer select-none text-sm font-medium text-fg">
          {label}
        </label>
        {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
      </div>
    </div>
  )
}
