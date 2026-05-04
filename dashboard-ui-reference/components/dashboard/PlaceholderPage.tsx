import { Card } from "@/components/ui/Card";

type PlaceholderPageProps = {
  title: string;
  description?: string;
};

export function PlaceholderPage({ title, description }: PlaceholderPageProps) {
  return (
    <div className="mx-auto max-w-content px-4 py-10 sm:px-8 lg:py-12">
      <h1 className="text-2xl font-semibold tracking-tight text-sv-text">{title}</h1>
      {description ? (
        <p className="mt-3 max-w-xl text-sm leading-relaxed text-sv-text-secondary">{description}</p>
      ) : null}
      <Card className="mt-8 max-w-xl p-5">
        <p className="text-sm leading-relaxed text-sv-text-secondary">
          This area is reserved for your program—when the full product is connected, your workspace
          data and actions will appear here.
        </p>
      </Card>
    </div>
  );
}
