import React, { useEffect, useRef } from "react";
import mermaid from "mermaid";

interface MermaidProps {
  chart: string;
}

const Mermaid: React.FC<MermaidProps> = ({ chart }) => {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;

    const renderMermaid = async () => {
      try {
        mermaid.initialize({ startOnLoad: false, theme: "default" });
        const { svg } = await mermaid.render(`mermaid-${Math.random()}`, chart);
        if (ref.current) {
          ref.current.innerHTML = svg;
        }
      } catch (err) {
        console.error("Mermaid render error:", err);
      }
    };

    renderMermaid();
  }, [chart]);

  return <div ref={ref} />;
};

export default Mermaid;
