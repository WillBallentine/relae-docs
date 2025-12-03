import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  tutorialSidebar: [
    {
      type: "doc",
      id: "intro",
      label: "Introduction",
    },
    {
      type: "category",
      label: "Quick Start",
      collapsed: false,
      items: [
        "quickstart/overview",
        "quickstart/setup",
        "quickstart/receive-your-first-webhook",
      ],
    },
    {
      type: "category",
      label: "Core Concepts",
      collapsed: false,
      items: ["core-concepts/what-is-relae"],
    },
    {
      type: "category",
      label: "Guides",
      collapsed: false,
      items: [
        "guides/managing-webhooks",
        "guides/dead-letter-queue",
        "guides/verifying-signatures",
        "guides/common-vendors",
      ],
    },
    {
      type: "category",
      label: "API",
      collapsed: false,
      items: ["api/authentication"],
    },
  ],
};

export default sidebars;
