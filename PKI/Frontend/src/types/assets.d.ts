// Lets TypeScript accept imports of non-code assets that webpack handles.

declare module '*.scss';
declare module '*.css';

declare module '*.svg' {
    const url: string;
    export default url;
}

declare module '*.png' {
    const url: string;
    export default url;
}

declare module '*.woff2' {
    const url: string;
    export default url;
}
