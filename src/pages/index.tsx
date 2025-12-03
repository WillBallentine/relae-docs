import type { ReactNode } from "react";
import clsx from "clsx";
import Link from "@docusaurus/Link";
import useBaseUrl from "@docusaurus/useBaseUrl";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import Layout from "@theme/Layout";
import Heading from "@theme/Heading";

import styles from "./index.module.css";

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  const startUrl = useBaseUrl("/quickstart/receive-your-first-webhook");
  const introUrl = useBaseUrl("/intro");
  const logoSrc = useBaseUrl("/img/relae_logo.svg"); // fixed

  return (
    <header className={clsx("hero hero--primary", styles.heroBanner)}>
      <div className="container">
        {/* Logo and title */}
        <div className={styles.heroLogoRow}>
          <img src={logoSrc} alt="Relae logo" className={styles.heroLogo} />
          <span className={styles.heroLogoText}>
            {siteConfig.title || "Relae"}
          </span>
        </div>

        {/* Headline */}
        <Heading as="h1" className={styles.heroTitle}>
          Receive and route webhooks — without infrastructure headaches
        </Heading>

        {/* Subtitle */}
        <p className={styles.heroSubtitle}>
          Reliable webhook ingestion, routing, retries, signing verification,
          and DLQ — all in one platform.
        </p>

        {/* Buttons */}
        <div className={styles.heroButtons}>
          <Link className={styles.buttonCta} to={startUrl}>
            Get Started <span className={styles.buttonArrow}>&rarr;</span>
          </Link>
          <Link className={styles.buttonOutline} to={introUrl}>
            Docs & Guides <span className={styles.buttonArrow}>&rarr;</span>
          </Link>
        </div>
      </div>
    </header>
  );
}

function FeatureCards() {
  const dashboardUrl = useBaseUrl("/guides/managing-webhooks");
  const dlqUrl = useBaseUrl("/guides/dead-letter-queue");
  const verifyUrl = useBaseUrl("/guides/verifying-signatures");

  const features = [
    {
      title: "Webhooks Dashboard",
      description:
        "Inspect every webhook request in real time. View headers, payloads, response logs, and event delivery history — all searchable and filterable.",
      url: dashboardUrl,
    },
    {
      title: "DLQ Dashboard",
      description:
        "Automatically capture failed webhook deliveries with full replay support. Prevent drops, detect issues early, and keep downstream systems healthy.",
      url: dlqUrl,
    },
    {
      title: "Verification",
      description:
        "Verify Relae signatures when webhooks are forwarded to your app.",
      url: verifyUrl,
    },
  ];

  return (
    <section className={styles.featuresSection}>
      <div className="container">
        <div className={styles.featuresGrid}>
          {features.map((feature) => (
            <div
              key={feature.title}
              className={clsx("card", styles.featureCard)}
            >
              <div className="card__body">
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </div>
              <div className="card__footer">
                <Link className="button button--primary" to={feature.url}>
                  Learn More
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="Relae Documentation"
      description="Learn how to receive, validate, and route webhooks using Relae."
    >
      <HomepageHeader />
      <main>
        <FeatureCards />
      </main>
    </Layout>
  );
}
