module.exports = {
    printWidth: 100,
    tabWidth: 4,
    useTabs: false,
    semi: false,
    singleQuote: true,
    trailingComma: 'es5',
    bracketSpacing: true,
    jsxBracketSameLine: false,
    arrowParens: 'avoid',
    proseWrap: 'never',
    overrides: [
        {
            files: '*.vue',
            options: {
                printWidth: 100,
            },
            parser: 'vue',
        },
    ],
}
