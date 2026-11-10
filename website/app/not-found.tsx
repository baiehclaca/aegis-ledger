import { Button, PageHero } from "@/components/ui";

export default function NotFound() {
  return (
    <PageHero label="404" title="Page not found." lead="This page does not exist.">
      <div className="mt-8"><Button href="/">Home</Button></div>
    </PageHero>
  );
}
