export * from "@kodama.page/ksp-core";

export function getFragmentCapability(name: string): string | null {
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    return params.get(name);
}

export function buildReadOnlyUrl(url: string, readerCapability: string): string { 
    const target = new URL(url); 
    target.hash = new URLSearchParams({ read: readerCapability }).toString();
    return target.toString(); 
}
