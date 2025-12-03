import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

const config: Config = {
  title: "Relae Documentation",
  tagline: "Reliable Webhook Management Made Simple",
  favicon: "img/favicon.ico",

  url: "https://docs.relaehook.com",
  baseUrl: "/",

  organizationName: "WillBallentine",
  projectName: "relae-docs",

  onBrokenLinks: "warn",
  onBrokenMarkdownLinks: "warn",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          routeBasePath: "/",
          editUrl: "https://github.com/WillBallentine/relae-docs/tree/main/",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: ["@docusaurus/theme-mermaid"],
  markdown: {
    mermaid: true,
  },

  themeConfig: {
    image: "img/relae-social-card.png",
    navbar: {
      title: "Relae",
      logo: {
        alt: "Relae Logo",
        src: "img/relae_logo.svg",
      },
      items: [
        {
          type: "docSidebar",
          sidebarId: "tutorialSidebar",
          position: "left",
          label: "Docs",
        },
        { href: "https://relaehook.com", label: "Home", position: "right" },
        {
          href: "https://relaehook.com/dashboard",
          label: "Dashboard",
          position: "right",
        },
        {
          href: "https://github.com/WillBallentine/relae-docs",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            { label: "Getting Started", to: "/quickstart/overview" },
            { label: "Core Concepts", to: "/core-concepts/what-is-relae" },
            { label: "API Reference", to: "/api/authentication" },
          ],
        },
        {
          title: "Product",
          items: [
            { label: "Dashboard", href: "https://relaehook.com/dashboard" },
            { label: "Pricing", href: "https://relaehook.com/#pricing" },
            { label: "Sign Up", href: "https://relaehook.com" },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/WillBallentine/relae-docs",
            },
            { label: "Support", href: "mailto:support@relaehook.com" },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Relae. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash", "json", "typescript"],
    },
    colorMode: {
      defaultMode: "dark",
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
