// OWASP Project Compliance Checker - JavaScript Client-Side Implementation

let currentResults = null;

// GitHub API configuration
const GITHUB_API_BASE = 'https://api.github.com';

// Simple in-memory cache to reduce API calls
const _apiCache = new Map();
const _utf8Decoder = new TextDecoder('utf-8');

function decodeBase64Utf8(base64Content) {
    const sanitized = String(base64Content || '').replace(/\s/g, '');
    const binaryString = atob(sanitized);
    const bytes = new Uint8Array(binaryString.length);

    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    return _utf8Decoder.decode(bytes);
}

// Parse GitHub URL to extract owner and repo
function parseGitHubUrl(url) {
    try {
        const urlObj = new URL(url.trim());
        if (urlObj.hostname !== 'github.com' && urlObj.hostname !== 'www.github.com') {
            throw new Error('Not a GitHub URL');
        }

        const pathParts = urlObj.pathname.split('/').filter(p => p);
        if (pathParts.length < 2) {
            throw new Error('Invalid GitHub repository URL');
        }

        return {
            owner: pathParts[0],
            repo: pathParts[1]
        };
    } catch (error) {
        throw new Error('Invalid GitHub repository URL. Please use format: https://github.com/owner/repo');
    }
}

// Make authenticated GitHub API request (with caching)
async function githubRequest(endpoint, token = null) {
    const cacheKey = endpoint;
    if (_apiCache.has(cacheKey)) {
        return _apiCache.get(cacheKey);
    }

    const headers = {
        'Accept': 'application/vnd.github.v3+json'
    };

    if (token) {
        headers['Authorization'] = `token ${token}`;
    }

    const response = await fetch(`${GITHUB_API_BASE}${endpoint}`, { headers });

    if (!response.ok) {
        if (response.status === 404) {
            throw new Error('Repository not found or is private');
        } else if (response.status === 403) {
            const rateLimitRemaining = response.headers.get('X-RateLimit-Remaining');
            if (rateLimitRemaining === '0') {
                throw new Error('GitHub API rate limit exceeded. Please provide a GitHub token or try again later.');
            }
            throw new Error('Access forbidden. The repository may be private or require authentication.');
        } else if (response.status === 401) {
            throw new Error('Invalid GitHub token. Please check your token and try again.');
        }
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    _apiCache.set(cacheKey, data);
    return data;
}

// Check if a file exists in the repository
async function checkFileExists(owner, repo, path, token) {
    try {
        await githubRequest(`/repos/${owner}/${repo}/contents/${path}`, token);
        return true;
    } catch {
        return false;
    }
}

// Check if a file exists and return its GitHub URL
async function checkFileExistsGetUrl(owner, repo, path, token) {
    try {
        const file = await githubRequest(`/repos/${owner}/${repo}/contents/${path}`, token);
        return { exists: true, url: file.html_url || `https://github.com/${owner}/${repo}/blob/main/${path}` };
    } catch {
        return { exists: false, url: null };
    }
}

// Get file content and its GitHub URL
async function getFileContentAndUrl(owner, repo, path, token) {
    try {
        const file = await githubRequest(`/repos/${owner}/${repo}/contents/${path}`, token);
        const content = decodeBase64Utf8(file.content);
        return { content, url: file.html_url || `https://github.com/${owner}/${repo}/blob/main/${path}` };
    } catch {
        return null;
    }
}

// Search code in a repository using GitHub's code search API (used sparingly)
async function searchCodeInRepo(owner, repo, query, token) {
    const cacheKey = `search:${owner}/${repo}:${query}`;
    if (_apiCache.has(cacheKey)) {
        return _apiCache.get(cacheKey);
    }
    try {
        const response = await githubRequest(
            `/search/code?q=${encodeURIComponent(query)}+repo:${owner}/${repo}&per_page=3`,
            token
        );
        _apiCache.set(cacheKey, response);
        return response;
    } catch {
        return { total_count: 0, items: [] };
    }
}

// Check if a directory exists in the repository
async function checkDirectoryExists(owner, repo, path, token) {
    try {
        const contents = await githubRequest(`/repos/${owner}/${repo}/contents/${path}`, token);
        return Array.isArray(contents);
    } catch {
        return false;
    }
}

// Get README content (lowercase for matching)
async function getReadmeContent(owner, repo, token) {
    try {
        const readme = await githubRequest(`/repos/${owner}/${repo}/readme`, token);
        const content = decodeBase64Utf8(readme.content).toLowerCase();
        return content;
    } catch (error) {
        console.error('Error fetching/decoding README:', error);
        return null;
    }
}

// Fetch contents of all GitHub Actions workflow files (up to 5)
async function getWorkflowContent(owner, repo, token) {
    try {
        const results = [];
        const workflowPath = '.github/workflows';
        const contents = await githubRequest(`/repos/${owner}/${repo}/contents/${workflowPath}`, token);
        for (const item of contents.slice(0, 5)) {
            if (item.type === 'file' && (item.name.endsWith('.yml') || item.name.endsWith('.yaml'))) {
                try {
                    const file = await githubRequest(`/repos/${owner}/${repo}/contents/${item.path}`, token);
                    const content = decodeBase64Utf8(file.content);
                    results.push({
                        name: item.name,
                        content: content,
                        url: file.html_url || `https://github.com/${owner}/${repo}/blob/main/${item.path}`
                    });
                } catch {
                    console.warn(`Failed to fetch workflow file: ${item.name}`);
                    continue;
                }
            }
        }
        return results;
    } catch {
        return [];
    }
}

// Build a GitHub file URL (fallback when html_url is unavailable)
function buildFileUrl(owner, repo, path) {
    return `https://github.com/${owner}/${repo}/blob/main/${path}`;
}

// Build a GitHub directory URL
function buildDirUrl(owner, repo, path) {
    return `https://github.com/${owner}/${repo}/tree/main/${path}`;
}

// Main compliance checker class
class ComplianceChecker {
    constructor(owner, repo, token = null) {
        this.owner = owner;
        this.repo = repo;
        this.token = token;
        this.results = {
            url: `https://github.com/${owner}/${repo}`,
            score: 0,
            maxScore: 100,
            percentage: 0,
            categories: {}
        };
        this.repoData = null;
        // Pre-fetched shared data (populated in runAllChecks)
        this._readme = null;
        this._gitignore = null;
        this._workflowFiles = [];
        this._deps = {};   // {python, npm, java, pipfile} content strings + source URLs
    }

    addCheck(category, name, passed, points = 1, details = '', howToFix = '') {
        if (!this.results.categories[category]) {
            this.results.categories[category] = {
                checks: [],
                score: 0,
                maxScore: 0
            };
        }

        if (passed) {
            this.results.categories[category].score += points;
            this.results.score += points;
        }

        this.results.categories[category].maxScore += points;
        this.results.categories[category].checks.push({
            name,
            passed,
            points: passed ? points : 0,
            maxPoints: points,
            details,
            howToFix: passed ? '' : howToFix
        });
    }

    async fetchRepositoryData() {
        this.repoData = await githubRequest(`/repos/${this.owner}/${this.repo}`, this.token);
    }

    // Pre-fetch shared data used by multiple checks to minimise API calls
    async prefetchSharedData() {
        this._readme = await getReadmeContent(this.owner, this.repo, this.token);
        this._gitignore = await getFileContentAndUrl(this.owner, this.repo, '.gitignore', this.token);
        this._workflowFiles = await getWorkflowContent(this.owner, this.repo, this.token);

        // Dependency/manifest files (any one of these may be present)
        const [reqTxt, pkgJson, pipfile, pomXml, gemfile, goMod] = await Promise.all([
            getFileContentAndUrl(this.owner, this.repo, 'requirements.txt', this.token),
            getFileContentAndUrl(this.owner, this.repo, 'package.json', this.token),
            getFileContentAndUrl(this.owner, this.repo, 'Pipfile', this.token),
            getFileContentAndUrl(this.owner, this.repo, 'pom.xml', this.token),
            getFileContentAndUrl(this.owner, this.repo, 'Gemfile', this.token),
            getFileContentAndUrl(this.owner, this.repo, 'go.mod', this.token),
        ]);
        this._deps = { reqTxt, pkgJson, pipfile, pomXml, gemfile, goMod };
    }

    // Search for any of the given keywords across all fetched dependency/manifest files
    _depsInclude(keywords) {
        const sources = [
            this._deps.reqTxt,
            this._deps.pkgJson,
            this._deps.pipfile,
            this._deps.pomXml,
            this._deps.gemfile,
            this._deps.goMod,
        ].filter(Boolean);
        for (const src of sources) {
            for (const kw of keywords) {
                if (src.content.toLowerCase().includes(kw.toLowerCase())) {
                    return { found: true, kw, url: src.url };
                }
            }
        }
        return { found: false };
    }

    // Search for keywords across all workflow files
    _workflowIncludes(keywords) {
        for (const wf of this._workflowFiles) {
            for (const kw of keywords) {
                if (wf.content.toLowerCase().includes(kw.toLowerCase())) {
                    return { found: true, kw, url: wf.url, name: wf.name };
                }
            }
        }
        return { found: false };
    }

    async checkGeneralCompliance() {
        const category = 'General Compliance & Governance';

        // 1. Project goal and scope
        const readme = this._readme;
        const goalKw = ['goal', 'purpose', 'about', 'overview', 'description'].find(kw => readme && readme.includes(kw));
        const hasGoal = !!goalKw;
        this.addCheck(category, 'Clearly defined project goal and scope', hasGoal, 1,
            hasGoal
                ? `README contains keyword "<strong>${goalKw}</strong>" — <a href="${buildFileUrl(this.owner, this.repo, 'README.md')}" target="_blank" rel="noopener">view README</a>`
                : 'Checked README for keywords: goal, purpose, about, overview, description — none found',
            'Add a clear project description in your README.md file. Include sections like "## About", "## Purpose", or "## Project Goal" to explain what your project does.');

        // 2. Open-source license
        const hasLicense = this.repoData.license !== null;
        const licenseUrl = `https://github.com/${this.owner}/${this.repo}/blob/main/LICENSE`;
        this.addCheck(category, 'Open-source license file present', hasLicense, 1,
            hasLicense
                ? `License: <a href="${licenseUrl}" target="_blank" rel="noopener">${this.repoData.license.name}</a> — detected via GitHub repository metadata`
                : 'No license detected in repository metadata (GitHub API: repo.license is null)',
            'Add a LICENSE file to your repository. Popular choices include MIT, Apache 2.0, or GPL. Use GitHub\'s "Add file > Create new file > LICENSE" wizard to add one.');

        // 3. README file
        const readmeResult = await checkFileExistsGetUrl(this.owner, this.repo, 'README.md', this.token);
        this.addCheck(category, 'README file provides project overview', readme !== null, 1,
            readme !== null
                ? `Found <a href="${readmeResult.url || buildFileUrl(this.owner, this.repo, 'README.md')}" target="_blank" rel="noopener">README.md</a> — checked via GitHub API <code>/repos/${this.owner}/${this.repo}/readme</code>`
                : 'README not found. Checked GitHub API: GET /repos/{owner}/{repo}/readme returned 404.',
            'Create a README.md file in the root directory with project overview, installation instructions, and usage examples.');

        // 4. OWASP organization
        const isOwasp = this.owner.toLowerCase() === 'owasp';
        this.addCheck(category, 'Under OWASP organization', isOwasp, 1,
            `Checked repository owner via GitHub API: <strong>${this.owner}</strong> (expected: owasp)`,
            'This check verifies if the repository is under the OWASP GitHub organization. Consider contributing to OWASP or following OWASP guidelines even if not under OWASP org.');

        // 5. Contributing guidelines
        const contribResult = await checkFileExistsGetUrl(this.owner, this.repo, 'CONTRIBUTING.md', this.token);
        this.addCheck(category, 'Contribution guidelines (CONTRIBUTING.md)', contribResult.exists, 1,
            contribResult.exists
                ? `Found <a href="${contribResult.url}" target="_blank" rel="noopener">CONTRIBUTING.md</a>`
                : 'Checked for CONTRIBUTING.md in repository root — not found',
            'Create a CONTRIBUTING.md file that explains how others can contribute to your project. Include guidelines for submitting issues, pull requests, and code style standards.');

        // 6. Issue tracker activity
        this.addCheck(category, 'Issue tracker is active', this.repoData.has_issues, 1,
            `GitHub API field <code>has_issues</code>: <strong>${this.repoData.has_issues}</strong>, open issues: ${this.repoData.open_issues_count}`,
            'Enable the Issues feature in your repository settings and actively respond to and manage issues.');

        // 7. Active maintainers (recent commits)
        try {
            const commits = await githubRequest(`/repos/${this.owner}/${this.repo}/commits?per_page=1`, this.token);
            const hasRecentCommits = commits.length > 0;
            const latestSha = hasRecentCommits ? commits[0].sha.substring(0, 7) : '';
            const commitUrl = hasRecentCommits ? commits[0].html_url : '';
            this.addCheck(category, 'Active maintainers with recent commits', hasRecentCommits, 1,
                hasRecentCommits
                    ? `Latest commit: <a href="${commitUrl}" target="_blank" rel="noopener">${latestSha}</a> — checked via GitHub API <code>/repos/${this.owner}/${this.repo}/commits</code>`
                    : 'No commits found in repository',
                'Ensure regular commits to show active maintenance. If the project is complete, add a note about its maintenance status in the README.');
        } catch {
            this.addCheck(category, 'Active maintainers with recent commits', false, 1,
                'Could not fetch commit history',
                'Make sure the repository has commits and is accessible. Regular commits demonstrate active maintenance.');
        }

        // 8. Code of Conduct
        const cocResult = await checkFileExistsGetUrl(this.owner, this.repo, 'CODE_OF_CONDUCT.md', this.token);
        this.addCheck(category, 'Code of Conduct present', cocResult.exists, 1,
            cocResult.exists
                ? `Found <a href="${cocResult.url}" target="_blank" rel="noopener">CODE_OF_CONDUCT.md</a>`
                : 'Checked for CODE_OF_CONDUCT.md in repository root — not found',
            'Add a CODE_OF_CONDUCT.md file to set expectations for community behavior. GitHub provides a template under "Insights > Community > Code of conduct".');

        // 9. Project roadmap or milestones
        const roadmapResult = await checkFileExistsGetUrl(this.owner, this.repo, 'ROADMAP.md', this.token);
        this.addCheck(category, 'Project roadmap or milestones documented', roadmapResult.exists, 1,
            roadmapResult.exists
                ? `Found <a href="${roadmapResult.url}" target="_blank" rel="noopener">ROADMAP.md</a>`
                : 'Checked for ROADMAP.md in repository root — not found',
            'Create a ROADMAP.md file or use GitHub Milestones (under "Issues" tab) to document planned features and project direction.');

        // 10. Collaborators
        try {
            const collaborators = await githubRequest(`/repos/${this.owner}/${this.repo}/collaborators?per_page=1`, this.token);
            const hasCollaborators = collaborators.length > 0;
            this.addCheck(category, 'Well-governed with active maintainers', hasCollaborators, 1,
                `GitHub API <code>/repos/${this.owner}/${this.repo}/collaborators</code> returned ${collaborators.length} result(s)`,
                'Add collaborators to your repository through Settings > Collaborators. Having multiple maintainers ensures better project governance.');
        } catch {
            this.addCheck(category, 'Well-governed with active maintainers', false, 1,
                'Could not fetch collaborators (may require authentication token with repo scope)',
                'Add collaborators to your repository through Settings > Collaborators. Having multiple maintainers ensures better project governance.');
        }
    }

    async checkDocumentation() {
        const category = 'Documentation & Usability';

        const readme = this._readme;
        const readmeUrl = buildFileUrl(this.owner, this.repo, 'README.md');

        // 11. Installation guide
        const installKw = ['install', 'setup', 'getting started', 'quick start'].find(kw => readme && readme.includes(kw));
        const hasInstall = !!installKw;
        this.addCheck(category, 'Installation guide in README', hasInstall, 1,
            hasInstall
                ? `README contains keyword "<strong>${installKw}</strong>" — <a href="${readmeUrl}" target="_blank" rel="noopener">view README</a>`
                : `Searched <a href="${readmeUrl}" target="_blank" rel="noopener">README</a> for: install, setup, getting started, quick start — none found`,
            'Add an installation section to your README.md. Include step-by-step setup instructions (e.g., ## Installation, ## Setup, or ## Getting Started).');

        // 12. Usage examples
        const usageKw = ['usage', 'example', 'how to use', 'tutorial'].find(kw => readme && readme.includes(kw));
        const hasUsage = !!usageKw;
        this.addCheck(category, 'Usage examples provided', hasUsage, 1,
            hasUsage
                ? `README contains keyword "<strong>${usageKw}</strong>" — <a href="${readmeUrl}" target="_blank" rel="noopener">view README</a>`
                : `Searched <a href="${readmeUrl}" target="_blank" rel="noopener">README</a> for: usage, example, how to use, tutorial — none found`,
            'Add usage examples to your README.md. Include code snippets showing how to use your project (e.g., ## Usage, ## Examples).');

        // 13. Wiki or docs directory
        const hasWiki = this.repoData.has_wiki;
        const hasDocs = await checkDirectoryExists(this.owner, this.repo, 'docs', this.token);
        this.addCheck(category, 'Wiki or docs/ directory', hasWiki || hasDocs, 1,
            `GitHub API <code>has_wiki</code>: <strong>${hasWiki}</strong>; ` +
            (hasDocs ? `<a href="${buildDirUrl(this.owner, this.repo, 'docs')}" target="_blank" rel="noopener">docs/</a> directory found`
                : 'docs/ directory: not found'),
            'Enable the Wiki feature in repository Settings, or create a "docs/" directory with detailed documentation files.');

        // 14. API documentation
        const [swaggerResult, openApiResult] = await Promise.all([
            checkFileExistsGetUrl(this.owner, this.repo, 'swagger.yaml', this.token),
            checkFileExistsGetUrl(this.owner, this.repo, 'openapi.yaml', this.token),
        ]);
        const hasApiDocs = await checkDirectoryExists(this.owner, this.repo, 'api-docs', this.token);
        const apiDocFound = swaggerResult.exists || openApiResult.exists || hasApiDocs;
        const apiDocLink = swaggerResult.exists
            ? `<a href="${swaggerResult.url}" target="_blank" rel="noopener">swagger.yaml</a>`
            : openApiResult.exists
                ? `<a href="${openApiResult.url}" target="_blank" rel="noopener">openapi.yaml</a>`
                : hasApiDocs
                    ? `<a href="${buildDirUrl(this.owner, this.repo, 'api-docs')}" target="_blank" rel="noopener">api-docs/</a>`
                    : null;
        this.addCheck(category, 'API documentation available', apiDocFound, 1,
            apiDocFound
                ? `Found ${apiDocLink}`
                : 'Checked for swagger.yaml, openapi.yaml, api-docs/ — none found',
            'If your project has an API, document it using OpenAPI/Swagger. Create a swagger.yaml or openapi.yaml file, or add documentation in an api-docs/ directory.');

        // 15. Code comments — check first few source files in root
        let hasComments = false;
        let commentsDetails = 'Checked root-level source files for #, //, /* comment markers';
        let commentsFileUrl = null;
        try {
            const contents = await githubRequest(`/repos/${this.owner}/${this.repo}/contents/`, this.token);
            const extensions = ['.py', '.js', '.java', '.go', '.rs', '.ts', '.jsx', '.tsx'];
            const sourceFiles = contents.filter(i => i.type === 'file' && extensions.some(e => i.name.endsWith(e)));
            for (const item of sourceFiles.slice(0, 8)) {
                try {
                    const file = await githubRequest(`/repos/${this.owner}/${this.repo}/contents/${item.path}`, this.token);
                    const content = decodeBase64Utf8(file.content);

                    if (content.includes('#') || content.includes('//') || content.includes('/*')) {
                        hasComments = true;
                        commentsFileUrl = file.html_url;
                        commentsDetails = `Found comments in <a href="${commentsFileUrl}" target="_blank" rel="noopener">${item.name}</a> (searched for: #, //, /*)`;
                        break;
                    }
                } catch { continue; }
            }
            if (!hasComments) commentsDetails = `Checked ${sourceFiles.length} source file(s) in root — no comment markers found`;
        } catch { /* leave defaults */ }
        this.addCheck(category, 'Inline code comments present', hasComments, 1, commentsDetails,
            'Add meaningful comments to your code to explain complex logic. Use docstrings for functions/classes and inline comments for non-obvious code.');

        // 16. Scripts documentation
        const scriptDocResult = await checkFileExistsGetUrl(this.owner, this.repo, 'scripts/README.md', this.token);
        this.addCheck(category, 'Scripts and configuration documented', scriptDocResult.exists, 1,
            scriptDocResult.exists
                ? `Found <a href="${scriptDocResult.url}" target="_blank" rel="noopener">scripts/README.md</a>`
                : 'Checked for scripts/README.md — not found',
            'If you have a scripts/ directory, create scripts/README.md explaining what each script does and how to use them.');

        // 17. FAQ or troubleshooting guide
        const [faqResult, troubleResult] = await Promise.all([
            checkFileExistsGetUrl(this.owner, this.repo, 'FAQ.md', this.token),
            checkFileExistsGetUrl(this.owner, this.repo, 'TROUBLESHOOTING.md', this.token),
        ]);
        const hasFaqOrTrouble = faqResult.exists || troubleResult.exists;
        const faqLinks = [
            faqResult.exists ? `<a href="${faqResult.url}" target="_blank" rel="noopener">FAQ.md</a>` : null,
            troubleResult.exists ? `<a href="${troubleResult.url}" target="_blank" rel="noopener">TROUBLESHOOTING.md</a>` : null,
        ].filter(Boolean).join(', ');
        this.addCheck(category, 'FAQ or troubleshooting guide', hasFaqOrTrouble, 1,
            hasFaqOrTrouble ? `Found: ${faqLinks}` : 'Checked for FAQ.md and TROUBLESHOOTING.md — neither found',
            'Create a FAQ.md or TROUBLESHOOTING.md file to help users solve common problems.');

        // 18. Error messages — search for error/exception patterns in deps or README
        const errorInDeps = this._depsInclude(['error', 'exception', 'raise', 'throw']);
        const errorInReadme = readme && readme.includes('error');
        const hasErrorHandling = errorInDeps.found || errorInReadme;
        this.addCheck(category, 'Well-defined error messages', hasErrorHandling, 1,
            hasErrorHandling
                ? (errorInDeps.found
                    ? `Dependency/manifest file references error handling — <a href="${errorInDeps.url}" target="_blank" rel="noopener">view file</a>`
                    : `README mentions "error" — <a href="${readmeUrl}" target="_blank" rel="noopener">view README</a>`)
                : 'No error-handling patterns detected in dependency files or README',
            'Ensure your code provides clear, actionable error messages. Include what went wrong and how to fix it. Avoid generic messages like "Something went wrong".');

        // 19. Versioning strategy
        try {
            const releases = await githubRequest(`/repos/${this.owner}/${this.repo}/releases?per_page=1`, this.token);
            const hasVersions = releases.length > 0;
            const releaseUrl = hasVersions ? releases[0].html_url : null;
            this.addCheck(category, 'Clear versioning strategy', hasVersions, 1,
                hasVersions
                    ? `Found ${releases.length} release(s). Latest: <a href="${releaseUrl}" target="_blank" rel="noopener">${releases[0].tag_name}</a> — checked via GitHub API <code>/repos/${this.owner}/${this.repo}/releases</code>`
                    : 'No releases found via GitHub API /releases endpoint',
                'Create GitHub Releases to document version history. Tag each release: `git tag v1.0.0 && git push --tags`, then create a Release in the GitHub UI. Follow Semantic Versioning (semver.org).');
        } catch {
            this.addCheck(category, 'Clear versioning strategy', false, 1,
                'Could not fetch releases from GitHub API',
                'Create GitHub Releases: go to the "Releases" section in your repository and publish a new release. Use Semantic Versioning (MAJOR.MINOR.PATCH).');
        }

        // 20. CHANGELOG
        const changelogResult = await checkFileExistsGetUrl(this.owner, this.repo, 'CHANGELOG.md', this.token);
        this.addCheck(category, 'CHANGELOG maintained', changelogResult.exists, 1,
            changelogResult.exists
                ? `Found <a href="${changelogResult.url}" target="_blank" rel="noopener">CHANGELOG.md</a>`
                : 'Checked for CHANGELOG.md — not found',
            'Create a CHANGELOG.md documenting notable changes for each version. Follow keepachangelog.com format. Update it with every release. Tools like `conventional-changelog` can automate this.');
    }

    async checkCodeQuality() {
        const category = 'Code Quality & Best Practices';

        // 21-22. Linters — check for actual linter config files
        const linterCandidates = [
            { path: '.eslintrc', name: 'ESLint' },
            { path: '.eslintrc.json', name: 'ESLint' },
            { path: '.eslintrc.js', name: 'ESLint' },
            { path: '.eslintrc.yml', name: 'ESLint' },
            { path: '.pylintrc', name: 'Pylint' },
            { path: '.flake8', name: 'Flake8' },
            { path: 'pyproject.toml', name: 'Python tool config (pyproject.toml)' },
            { path: '.rubocop.yml', name: 'RuboCop' },
            { path: 'tslint.json', name: 'TSLint' },
            { path: '.editorconfig', name: 'EditorConfig' },
            { path: '.prettierrc', name: 'Prettier' },
            { path: '.prettierrc.json', name: 'Prettier' },
            { path: 'setup.cfg', name: 'Python setup.cfg' },
        ];
        let linterResult = null;
        for (const lc of linterCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, lc.path, this.token);
            if (r.exists) { linterResult = { ...lc, url: r.url }; break; }
        }
        const hasLinter = linterResult !== null;
        const linterDetail = hasLinter
            ? `Found <a href="${linterResult.url}" target="_blank" rel="noopener">${linterResult.path}</a> (${linterResult.name})`
            : `Checked for: ${linterCandidates.map(l => l.path).join(', ')} — none found`;
        this.addCheck(category, 'Code follows style guide', hasLinter, 1, linterDetail,
            'Add a linter config to enforce code style. For JavaScript/TypeScript: `npx eslint --init`. For Python: add a [tool.pylint] section in pyproject.toml or create .pylintrc. For multi-language, use .editorconfig.');
        this.addCheck(category, 'Uses linters', hasLinter, 1, linterDetail,
            'Install and configure a linter and add it to CI. For JS: `npm install --save-dev eslint`. For Python: `pip install flake8 pylint`. Run `eslint .` or `flake8` in your GitHub Actions workflow to catch issues automatically.');

        // 23. Modular code — check for source/lib directories
        try {
            const contents = await githubRequest(`/repos/${this.owner}/${this.repo}/contents/`, this.token);
            const dirs = contents.filter(item => item.type === 'dir');
            const numDirs = dirs.length;
            const dirList = dirs.slice(0, 6).map(d => `<a href="${buildDirUrl(this.owner, this.repo, d.name)}" target="_blank" rel="noopener">${d.name}/</a>`).join(', ');
            this.addCheck(category, 'Code is modular and maintainable', numDirs >= 2, 1,
                `Found ${numDirs} directories in root: ${dirList}${numDirs > 6 ? '…' : ''}`,
                'Organise code into logical directories (src/, lib/, utils/, services/). Each module should have a single responsibility. See: https://en.wikipedia.org/wiki/Single_responsibility_principle');
        } catch {
            this.addCheck(category, 'Code is modular and maintainable', false, 1,
                'Could not fetch repository root structure',
                'Organise code into logical directories and modules with clear separation of concerns.');
        }

        // 24. DRY principle — check for utility/shared directories
        const dryDirNames = ['utils', 'helpers', 'shared', 'common', 'lib', 'core', 'base'];
        let dryDir = null;
        for (const d of dryDirNames) {
            if (await checkDirectoryExists(this.owner, this.repo, d, this.token)) { dryDir = d; break; }
        }
        const hasDry = dryDir !== null;
        this.addCheck(category, 'Adheres to DRY principle', hasDry, 1,
            hasDry
                ? `Found shared code directory: <a href="${buildDirUrl(this.owner, this.repo, dryDir)}" target="_blank" rel="noopener">${dryDir}/</a>`
                : `Checked for utility/shared directories: ${dryDirNames.join(', ')} — none found`,
            'Create utility/helper directories (utils/, helpers/, shared/, lib/) to store reusable code. Avoid duplicating logic — each piece of code should exist in exactly one place (DRY = Don\'t Repeat Yourself).');

        // 25. Secure coding practices — check for security linter/scanner configs
        const secToolCandidates = [
            { path: '.bandit', name: 'Bandit' },
            { path: 'bandit.yaml', name: 'Bandit' },
            { path: '.safety-policy.json', name: 'Safety' },
            { path: 'semgrep.yml', name: 'Semgrep' },
            { path: '.semgrep.yml', name: 'Semgrep' },
            { path: 'semgrep.yaml', name: 'Semgrep' },
            { path: '.github/workflows', name: 'Security workflow' },
        ];
        let secToolResult = null;
        for (const st of secToolCandidates.slice(0, -1)) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, st.path, this.token);
            if (r.exists) { secToolResult = { ...st, url: r.url }; break; }
        }
        // Also check workflow files for bandit/semgrep/gosec
        const secInWorkflow = this._workflowIncludes(['bandit', 'semgrep', 'gosec', 'brakeman', 'eslint-security']);
        const hasSecTool = secToolResult !== null || secInWorkflow.found;
        this.addCheck(category, 'Secure coding practices followed', hasSecTool, 1,
            hasSecTool
                ? (secToolResult
                    ? `Found security tool config: <a href="${secToolResult.url}" target="_blank" rel="noopener">${secToolResult.path}</a> (${secToolResult.name})`
                    : `Detected "${secInWorkflow.kw}" in CI workflow <a href="${secInWorkflow.url}" target="_blank" rel="noopener">${secInWorkflow.name}</a>`)
                : `Checked for security linters: ${secToolCandidates.map(s => s.path).join(', ')} — none found`,
            'Add security linting to your project. For Python: `pip install bandit` then `bandit -r .`. For multi-language: use Semgrep (semgrep.dev). Add security scanning to your CI/CD pipeline.');

        // 26. No hardcoded credentials — check .gitignore covers .env AND .env.example exists
        const gitignore = this._gitignore;
        const envExampleResult = await checkFileExistsGetUrl(this.owner, this.repo, '.env.example', this.token);
        const envInGitignore = gitignore && gitignore.content.includes('.env');
        const hasCredProtection = envInGitignore || envExampleResult.exists;
        let credDetails = '';
        if (envInGitignore && envExampleResult.exists) {
            credDetails = `.env excluded in <a href="${gitignore.url}" target="_blank" rel="noopener">.gitignore</a> and <a href="${envExampleResult.url}" target="_blank" rel="noopener">.env.example</a> present`;
        } else if (envInGitignore) {
            credDetails = `.env excluded in <a href="${gitignore.url}" target="_blank" rel="noopener">.gitignore</a> (no .env.example found)`;
        } else if (envExampleResult.exists) {
            credDetails = `<a href="${envExampleResult.url}" target="_blank" rel="noopener">.env.example</a> found${gitignore ? ` but .gitignore does not mention .env` : ' (no .gitignore found)'}`;
        } else {
            credDetails = `Checked: .gitignore${gitignore ? ` (<a href="${gitignore.url}" target="_blank" rel="noopener">view</a>, no .env entry)` : ' (not found)'} and .env.example (not found)`;
        }
        this.addCheck(category, 'No hardcoded credentials or secrets', hasCredProtection, 1, credDetails,
            'Add .env to .gitignore immediately. Create a .env.example with placeholder values as a template. Use environment variables for all secrets. Run `git secrets --scan` or `trufflehog` to check for accidentally committed secrets.');

        // 27. Parameterized queries — search dependency files for ORM/query libraries
        const ormKeywords = ['sqlalchemy', 'hibernate', 'sequelize', 'typeorm', 'prisma', 'django.db', 'activerecord', 'ecto', 'pg', 'mysql2', 'psycopg2', 'pymysql', 'knex'];
        const ormMatch = this._depsInclude(ormKeywords);
        this.addCheck(category, 'Uses parameterized queries', ormMatch.found, 1,
            ormMatch.found
                ? `Found ORM/query library "<strong>${ormMatch.kw}</strong>" in <a href="${ormMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched requirements.txt, package.json, pom.xml, Gemfile, go.mod for: ${ormKeywords.join(', ')} — none found`,
            'Use an ORM (SQLAlchemy for Python, Hibernate for Java, Sequelize for Node.js) or parameterized queries to prevent SQL injection. Never concatenate user input into SQL strings. Example: `cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])`');

        // 28. Strong cryptographic algorithms — search deps for strong crypto libs; flag weak ones
        const strongCryptoKw = ['bcrypt', 'argon2', 'pbkdf2', 'scrypt', 'nacl', 'libsodium', 'cryptography', 'passlib', 'pynacl'];
        const weakCryptoKw = ['md5', 'sha1', 'des', 'rc4', '3des'];
        const strongMatch = this._depsInclude(strongCryptoKw);
        // Only flag weak crypto when found in actual dependency files (not documentation)
        const weakMatch = this._depsInclude(weakCryptoKw);
        const hasStrongCrypto = strongMatch.found && !weakMatch.found;
        let cryptoDetails = '';
        if (strongMatch.found && !weakMatch.found) {
            cryptoDetails = `Strong crypto library "<strong>${strongMatch.kw}</strong>" in <a href="${strongMatch.url}" target="_blank" rel="noopener">dependency file</a>`;
        } else if (weakMatch.found) {
            cryptoDetails = `⚠️ Potential weak crypto keyword "<strong>${weakMatch.kw}</strong>" found in <a href="${weakMatch.url}" target="_blank" rel="noopener">dependency file</a>`;
        } else {
            cryptoDetails = `Searched dependency files for strong crypto (${strongCryptoKw.join(', ')}) and weak crypto (${weakCryptoKw.join(', ')}) — nothing detected`;
        }
        this.addCheck(category, 'Strong cryptographic algorithms', hasStrongCrypto, 1, cryptoDetails,
            'Use strong cryptographic algorithms: bcrypt or Argon2 for password hashing, AES-256 for encryption. Avoid MD5 and SHA1 for any security-sensitive purpose. Use a well-maintained crypto library (bcrypt for Node.js, passlib for Python).');

        // 29. Input validation — search deps for validation libraries
        const validationKw = ['marshmallow', 'pydantic', 'cerberus', 'voluptuous', 'joi', 'yup', 'zod', 'ajv', 'express-validator', 'class-validator', 'django.forms', 'javax.validation', 'jakarta.validation', 'wtforms'];
        const validMatch = this._depsInclude(validationKw);
        this.addCheck(category, 'Input validation implemented', validMatch.found, 1,
            validMatch.found
                ? `Validation library "<strong>${validMatch.kw}</strong>" in <a href="${validMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for: ${validationKw.join(', ')} — none found`,
            'Implement server-side input validation using a library. For Python: Pydantic or marshmallow. For Node.js: Joi, Zod, or express-validator. Validate all user inputs for type, length, format, and allowed values.');

        // 30. Output encoding for XSS prevention — search deps for sanitization/escaping libs
        const xssKw = ['dompurify', 'sanitize-html', 'bleach', 'markupsafe', 'xss', 'html-escaper', 'escape-html', 'django.utils.html', 'jinja2', 'handlebars', 'react'];
        const xssMatch = this._depsInclude(xssKw);
        this.addCheck(category, 'Output encoding for XSS prevention', xssMatch.found, 1,
            xssMatch.found
                ? `XSS-protection/encoding library "<strong>${xssMatch.kw}</strong>" in <a href="${xssMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for: ${xssKw.join(', ')} — none found`,
            'Use output encoding to prevent XSS. For HTML output: DOMPurify (JS), bleach (Python), or your framework\'s built-in escaping. Never insert untrusted data into innerHTML. Add a Content Security Policy (CSP) header.');
    }

    async checkSecurity() {
        const category = 'Security & OWASP Compliance';

        // 31. Security policy
        const secResult = await checkFileExistsGetUrl(this.owner, this.repo, 'SECURITY.md', this.token);
        this.addCheck(category, 'Security policy (SECURITY.md)', secResult.exists, 1,
            secResult.exists
                ? `Found <a href="${secResult.url}" target="_blank" rel="noopener">SECURITY.md</a>`
                : 'Checked for SECURITY.md in repository root — not found',
            'Create SECURITY.md with your security policy. Include: how to report vulnerabilities (private email or GitHub private reporting), response timeline, and supported versions. GitHub highlights this file automatically.');

        // 32. Dependency scanning
        const depbotResult = await checkFileExistsGetUrl(this.owner, this.repo, '.github/dependabot.yml', this.token);
        this.addCheck(category, 'Dependency scanning configured', depbotResult.exists, 1,
            depbotResult.exists
                ? `Found <a href="${depbotResult.url}" target="_blank" rel="noopener">.github/dependabot.yml</a>`
                : 'Checked for .github/dependabot.yml — not found',
            'Create .github/dependabot.yml to enable automatic dependency updates. Dependabot opens PRs when vulnerabilities are found. See: https://docs.github.com/en/code-security/dependabot');

        // 33. Secure headers — check for Helmet.js, nginx config, or security header middleware in deps
        const headerKw = ['helmet', 'django-csp', 'flask-talisman', 'rack-protection', 'secure', 'talisman'];
        const nginxResult = await checkFileExistsGetUrl(this.owner, this.repo, 'nginx.conf', this.token);
        const headerMatch = this._depsInclude(headerKw);
        const headerInWorkflow = this._workflowIncludes(['helmet', 'csp', 'hsts']);
        const hasSecureHeaders = headerMatch.found || nginxResult.exists;
        this.addCheck(category, 'Uses secure headers (CSP, HSTS, etc.)', hasSecureHeaders, 1,
            hasSecureHeaders
                ? (headerMatch.found
                    ? `Found header middleware "<strong>${headerMatch.kw}</strong>" in <a href="${headerMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                    : `Found <a href="${nginxResult.url}" target="_blank" rel="noopener">nginx.conf</a> (review for security headers)`)
                : `Checked dependency files for Helmet.js/flask-talisman/django-csp and nginx.conf — none found`,
            'Add HTTP security headers. For Node.js: `npm install helmet` then `app.use(helmet())`. For Python/Flask: `pip install flask-talisman`. For Django: `pip install django-csp`. Headers to set: Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options.');

        // 34. Input validation enforced (security context)
        const validKwSec = ['marshmallow', 'pydantic', 'cerberus', 'joi', 'yup', 'zod', 'express-validator', 'class-validator', 'django.forms', 'javax.validation', 'wtforms'];
        const validMatchSec = this._depsInclude(validKwSec);
        this.addCheck(category, 'Input validation enforced', validMatchSec.found, 1,
            validMatchSec.found
                ? `Validation library "<strong>${validMatchSec.kw}</strong>" in <a href="${validMatchSec.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for validation libraries — none detected`,
            'Enforce server-side input validation on all user inputs. Use a validation library (Pydantic, Joi, Zod). Never trust client-side validation alone. Validate type, length, format, and allowed character sets.');

        // 35. RBAC — check deps for auth/permission libraries
        const rbacKw = ['casbin', 'permissions', 'django.contrib.auth', 'flask-principal', 'cancan', 'pundit', 'casl', 'accesscontrol', 'spring-security', 'acl'];
        const rbacMatch = this._depsInclude(rbacKw);
        this.addCheck(category, 'RBAC implemented where applicable', rbacMatch.found, 1,
            rbacMatch.found
                ? `Found RBAC/permission library "<strong>${rbacMatch.kw}</strong>" in <a href="${rbacMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for RBAC/permission libraries: ${rbacKw.join(', ')} — none found`,
            'Implement Role-Based Access Control (RBAC). Use your framework\'s auth system (Django auth, Spring Security) or a library like Casbin. Define roles (admin, user, viewer) and check permissions for every sensitive operation.');

        // 36. Secure authentication
        const authKw = ['passport', 'bcrypt', 'argon2', 'auth0', 'jwt', 'jose', 'firebase', 'django.contrib.auth', 'devise', 'spring-security', 'flask-login', 'authlib', 'nextauth'];
        const authMatch = this._depsInclude(authKw);
        this.addCheck(category, 'Secure authentication mechanisms', authMatch.found, 1,
            authMatch.found
                ? `Found auth library "<strong>${authMatch.kw}</strong>" in <a href="${authMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for auth libraries: ${authKw.join(', ')} — none found`,
            'Use established authentication libraries. For Node.js: Passport.js with bcrypt. For Python: Django auth or Flask-Login. For Java: Spring Security. Never implement auth from scratch. Use MFA and short-lived tokens.');

        // 37. Secrets stored securely — check .gitignore + .env.example
        const gitignore = this._gitignore;
        const envExResult = await checkFileExistsGetUrl(this.owner, this.repo, '.env.example', this.token);
        const envGit = gitignore && gitignore.content.includes('.env');
        const hasSecretMgmt = envGit || envExResult.exists;
        let secretDetails = '';
        if (envGit && envExResult.exists) {
            secretDetails = `.env in <a href="${gitignore.url}" target="_blank" rel="noopener">.gitignore</a>, <a href="${envExResult.url}" target="_blank" rel="noopener">.env.example</a> present`;
        } else if (envGit) {
            secretDetails = `.env excluded in <a href="${gitignore.url}" target="_blank" rel="noopener">.gitignore</a>`;
        } else if (envExResult.exists) {
            secretDetails = `<a href="${envExResult.url}" target="_blank" rel="noopener">.env.example</a> found; .gitignore does not mention .env — add it`;
        } else {
            secretDetails = `No .gitignore .env exclusion or .env.example found — secrets may be at risk`;
        }
        this.addCheck(category, 'Secrets stored securely', hasSecretMgmt, 1, secretDetails,
            'Add .env to .gitignore immediately. Create a .env.example with placeholder values. Consider GitHub Secrets or HashiCorp Vault for production secrets. Run `git log --all --full-history -- "**/.env"` to check if secrets were ever committed.');

        // 38. HTTPS — check for HTTPS-enforcement patterns in deps or config files
        const httpsKw = ['SECURE_SSL_REDIRECT', 'force_https', 'ssl_redirect', 'redirectToHttps', 'flask-talisman', 'hsts'];
        const httpsMatch = this._depsInclude(httpsKw);
        const httpsInReadme = this._readme && this._readme.includes('https');
        const hasHTTPS = httpsMatch.found || httpsInReadme;
        this.addCheck(category, 'Uses HTTPS for communication', hasHTTPS, 1,
            hasHTTPS
                ? (httpsMatch.found
                    ? `Found HTTPS enforcement "<strong>${httpsMatch.kw}</strong>" in <a href="${httpsMatch.url}" target="_blank" rel="noopener">dependency/config file</a>`
                    : `README mentions HTTPS — <a href="${buildFileUrl(this.owner, this.repo, 'README.md')}" target="_blank" rel="noopener">view README</a>`)
                : 'No HTTPS enforcement config found in dependency files or README',
            'Enforce HTTPS everywhere. For Django: `SECURE_SSL_REDIRECT = True`. For Express: use Helmet or redirect HTTP→HTTPS. Configure HSTS in your web server. Use Let\'s Encrypt for free certificates.');

        // 39. OWASP ASVS — check README and SECURITY.md for ASVS mentions
        const asvsInReadme = this._readme && (this._readme.includes('asvs') || this._readme.includes('application security verification'));
        let asvsDetails = '';
        if (asvsInReadme) {
            asvsDetails = `README mentions ASVS — <a href="${buildFileUrl(this.owner, this.repo, 'README.md')}" target="_blank" rel="noopener">view README</a>`;
        } else if (secResult.exists) {
            // Check SECURITY.md content
            const secContent = await getFileContentAndUrl(this.owner, this.repo, 'SECURITY.md', this.token);
            const asvsInSec = secContent && secContent.content.toLowerCase().includes('asvs');
            if (asvsInSec) {
                asvsDetails = `ASVS referenced in <a href="${secResult.url}" target="_blank" rel="noopener">SECURITY.md</a>`;
            } else {
                asvsDetails = 'Checked README and SECURITY.md for ASVS mentions — not found';
            }
        } else {
            asvsDetails = 'Checked README for ASVS mentions — not found; no SECURITY.md present';
        }
        const hasASVS = asvsInReadme || (secResult.exists && asvsDetails.includes('ASVS referenced'));
        this.addCheck(category, 'Adheres to OWASP ASVS', hasASVS, 1, asvsDetails,
            'Review the OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/. Choose Level 1, 2, or 3 and document which requirements you meet in SECURITY.md or a dedicated SECURITY-ASVS.md.');

        // 40. Secure cookie attributes — check deps for cookie security libs or config
        const cookieKw = ['cookie-session', 'express-session', 'django.middleware.csrf', 'samesite', 'httponly', 'secure_cookies', 'flask-session'];
        const cookieMatch = this._depsInclude(cookieKw);
        this.addCheck(category, 'Secure cookie attributes', cookieMatch.found, 1,
            cookieMatch.found
                ? `Found cookie/session library "<strong>${cookieMatch.kw}</strong>" in <a href="${cookieMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for cookie/session management: ${cookieKw.join(', ')} — none found`,
            'Set secure cookie attributes: HttpOnly (prevents XSS), Secure (HTTPS only), SameSite=Strict or Lax (prevents CSRF). Example: `res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" })`');

        // 41. No unnecessary ports exposed — check Dockerfile EXPOSE directives
        const dockerfileData = await getFileContentAndUrl(this.owner, this.repo, 'Dockerfile', this.token);
        let portDetails = '';
        let hasPortControl = false;
        if (dockerfileData) {
            // Match EXPOSE with port numbers, optionally followed by /protocol (e.g., EXPOSE 80/tcp)
            const exposeCount = (dockerfileData.content.match(/^EXPOSE\s+\d+(?:\/(?:tcp|udp))?/gmi) || []).length;
            hasPortControl = exposeCount <= 2;
            portDetails = `<a href="${dockerfileData.url}" target="_blank" rel="noopener">Dockerfile</a> exposes ${exposeCount} port(s) — ${exposeCount <= 2 ? 'acceptable' : 'consider reducing'}`;
        } else {
            hasPortControl = true; // No containers = no exposed ports
            portDetails = 'No Dockerfile found — checked via GitHub API /contents/Dockerfile (no container port exposure)';
        }
        this.addCheck(category, 'No unnecessary ports exposed', hasPortControl, 1, portDetails,
            'In your Dockerfile, only EXPOSE ports your app actually uses. Remove debug ports from production builds. Use multi-stage builds to minimise attack surface.');

        // 42. Logs security events — check for audit/security logging in deps
        const secLogKw = ['audit-log', 'auditlog', 'django-auditlog', 'structlog', 'python-audit', 'sentry', 'audit'];
        const secLogMatch = this._depsInclude(secLogKw);
        this.addCheck(category, 'Logs security events', secLogMatch.found, 1,
            secLogMatch.found
                ? `Found logging/audit library "<strong>${secLogMatch.kw}</strong>" in <a href="${secLogMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for audit/security logging: ${secLogKw.join(', ')} — none found`,
            'Log security-relevant events: failed logins, authorisation failures, privilege changes, and data exports. Include who, what, when, and from where. Use structured logging. Example: `logger.warning("Failed login for %s from %s", user, ip)`');

        // 43. Least privilege — check workflow files for `permissions:` blocks
        const permInWorkflow = this._workflowIncludes(['permissions:']);
        const hasLeastPriv = permInWorkflow.found;
        this.addCheck(category, 'Least privilege principle', hasLeastPriv, 1,
            hasLeastPriv
                ? `Found <code>permissions:</code> block in <a href="${permInWorkflow.url}" target="_blank" rel="noopener">${permInWorkflow.name}</a> (CI/CD least-privilege configured)`
                : `Checked ${this._workflowFiles.length} workflow file(s) for <code>permissions:</code> — not found`,
            'Apply least privilege: in GitHub Actions, add `permissions: read-all` at the workflow level and grant only specific write permissions per job. For application code, give each service only the minimum permissions needed.');

        // 44. No unsafe dependencies — check for Snyk config or dependabot as evidence
        const snykResult = await checkFileExistsGetUrl(this.owner, this.repo, '.snyk', this.token);
        const depAuditInWf = this._workflowIncludes(['npm audit', 'pip-audit', 'safety check', 'snyk test', 'bundle-audit', 'govulncheck', 'trivy']);
        const hasDepSec = snykResult.exists || depbotResult.exists || depAuditInWf.found;
        let depSecDetails = '';
        if (snykResult.exists) depSecDetails = `Found <a href="${snykResult.url}" target="_blank" rel="noopener">.snyk</a> configuration`;
        else if (depbotResult.exists) depSecDetails = `Dependabot configured (see check #32)`;
        else if (depAuditInWf.found) depSecDetails = `Dependency audit command "<strong>${depAuditInWf.kw}</strong>" in <a href="${depAuditInWf.url}" target="_blank" rel="noopener">${depAuditInWf.name}</a>`;
        else depSecDetails = 'No dependency security scanning found (.snyk, dependabot.yml, npm audit, pip-audit, snyk test)';
        this.addCheck(category, 'No outdated/unsafe dependencies', hasDepSec, 1, depSecDetails,
            'Enable dependency scanning: add .github/dependabot.yml, use Snyk (snyk.io), or add `npm audit --audit-level=high` / `pip-audit` to your CI pipeline. Review and update vulnerable dependencies promptly.');

        // 45. OWASP Top 10 — check README and SECURITY.md
        const top10InReadme = this._readme && (this._readme.includes('owasp top 10') || this._readme.includes('owasp top ten') || this._readme.includes('a01') || this._readme.includes('a10'));
        let top10Details = '';
        let hasTop10 = top10InReadme;
        if (top10InReadme) {
            top10Details = `README references OWASP Top 10 — <a href="${buildFileUrl(this.owner, this.repo, 'README.md')}" target="_blank" rel="noopener">view README</a>`;
        } else {
            top10Details = 'Checked README for OWASP Top 10 references (owasp top 10, A01, A10) — not found';
        }
        this.addCheck(category, 'Complies with OWASP Top 10', hasTop10, 1, top10Details,
            'Review and address the OWASP Top 10: https://owasp.org/www-project-top-ten/. Document mitigations in SECURITY.md. Use SAST tools (CodeQL, Semgrep) to automatically detect common vulnerability classes in CI.');
    }

    async checkCICD() {
        const category = 'CI/CD & DevSecOps';

        // 46. Tests directory
        const testsDirs = ['tests', 'test', '__tests__', 'spec'];
        let testsDirFound = null;
        for (const d of testsDirs) {
            if (await checkDirectoryExists(this.owner, this.repo, d, this.token)) { testsDirFound = d; break; }
        }
        const hasTests = testsDirFound !== null;
        this.addCheck(category, 'Automated unit tests implemented', hasTests, 1,
            hasTests
                ? `Found <a href="${buildDirUrl(this.owner, this.repo, testsDirFound)}" target="_blank" rel="noopener">${testsDirFound}/</a> directory`
                : `Checked for test directories: ${testsDirs.join(', ')} — none found`,
            'Create a test directory and write unit tests. Use pytest for Python, Jest for JS/TS, JUnit for Java, or Go test for Go. Add test execution to your CI pipeline. Aim for at least 70% coverage.');

        // 47. CI configuration
        const hasGHActions = await checkDirectoryExists(this.owner, this.repo, '.github/workflows', this.token);
        const [gitlabCI, travis, jenkins] = await Promise.all([
            checkFileExistsGetUrl(this.owner, this.repo, '.gitlab-ci.yml', this.token),
            checkFileExistsGetUrl(this.owner, this.repo, '.travis.yml', this.token),
            checkFileExistsGetUrl(this.owner, this.repo, 'Jenkinsfile', this.token),
        ]);
        const hasCI = hasGHActions || gitlabCI.exists || travis.exists || jenkins.exists;
        let ciDetail = '';
        if (hasGHActions) ciDetail = `GitHub Actions — <a href="${buildDirUrl(this.owner, this.repo, '.github/workflows')}" target="_blank" rel="noopener">.github/workflows/</a>`;
        else if (gitlabCI.exists) ciDetail = `GitLab CI — <a href="${gitlabCI.url}" target="_blank" rel="noopener">.gitlab-ci.yml</a>`;
        else if (travis.exists) ciDetail = `Travis CI — <a href="${travis.url}" target="_blank" rel="noopener">.travis.yml</a>`;
        else if (jenkins.exists) ciDetail = `Jenkins — <a href="${jenkins.url}" target="_blank" rel="noopener">Jenkinsfile</a>`;
        else ciDetail = 'No CI configuration found (.github/workflows/, .gitlab-ci.yml, .travis.yml, Jenkinsfile)';
        this.addCheck(category, 'Continuous Integration configured', hasCI, 1, ciDetail,
            'Set up CI using GitHub Actions (free for public repos). Create .github/workflows/ci.yml to run tests and checks on every PR. See: https://docs.github.com/en/actions/quickstart');

        // 48. Security scanning in CI — read actual workflow file content
        const secScanTools = ['codeql', 'semgrep', 'sonarcloud', 'sonarqube', 'snyk', 'trivy', 'bandit', 'safety', 'gosec', 'brakeman', 'dependabot', 'gitleaks', 'trufflehog'];
        const secScanMatch = this._workflowIncludes(secScanTools);
        this.addCheck(category, 'CI/CD includes security scanning', secScanMatch.found, 1,
            secScanMatch.found
                ? `Found security tool "<strong>${secScanMatch.kw}</strong>" in <a href="${secScanMatch.url}" target="_blank" rel="noopener">${secScanMatch.name}</a>`
                : `Checked ${this._workflowFiles.length} workflow file(s) for: ${secScanTools.join(', ')} — none found`,
            'Add security scanning to CI. Enable GitHub\'s CodeQL: Actions > New workflow > Security > CodeQL Analysis. Also add `npm audit` or `pip-audit` for dependency scanning.');

        // 49. Dependency scanning automated
        const depbotYml = await checkFileExistsGetUrl(this.owner, this.repo, '.github/dependabot.yml', this.token);
        const depScanMatch = this._workflowIncludes(['npm audit', 'pip-audit', 'snyk', 'safety check', 'bundle-audit', 'govulncheck', 'dependabot']);
        const hasDepScan = depbotYml.exists || depScanMatch.found;
        this.addCheck(category, 'Dependency scanning automated', hasDepScan, 1,
            hasDepScan
                ? (depbotYml.exists
                    ? `<a href="${depbotYml.url}" target="_blank" rel="noopener">.github/dependabot.yml</a> present`
                    : `Dependency audit "<strong>${depScanMatch.kw}</strong>" in <a href="${depScanMatch.url}" target="_blank" rel="noopener">${depScanMatch.name}</a>`)
                : 'No automated dependency scanning found (.github/dependabot.yml or audit commands in workflows)',
            'Enable Dependabot: create .github/dependabot.yml with your package ecosystem. Or add `npm audit --audit-level=high` / `pip-audit` to your CI workflow.');

        // 50. Code coverage
        const coverageCandidates = ['.coveragerc', '.nycrc', '.nycrc.json', 'codecov.yml', '.codecov.yml', 'coveralls.yml'];
        let coverageFileResult = null;
        for (const cf of coverageCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, cf, this.token);
            if (r.exists) { coverageFileResult = { path: cf, url: r.url }; break; }
        }
        const coverageInWf = this._workflowIncludes(['coverage', 'codecov', 'coveralls', '--cov', 'nyc', 'istanbul']);
        const hasCoverage = coverageFileResult !== null || coverageInWf.found;
        this.addCheck(category, 'Code coverage reports generated', hasCoverage, 1,
            hasCoverage
                ? (coverageFileResult
                    ? `Found <a href="${coverageFileResult.url}" target="_blank" rel="noopener">${coverageFileResult.path}</a>`
                    : `Coverage tool "<strong>${coverageInWf.kw}</strong>" in <a href="${coverageInWf.url}" target="_blank" rel="noopener">${coverageInWf.name}</a>`)
                : `Checked for: ${coverageCandidates.join(', ')} and coverage commands in ${this._workflowFiles.length} workflow(s) — none found`,
            'Set up code coverage. For Python: `pip install pytest-cov` and run `pytest --cov=. --cov-report=xml`. For Node.js: use Jest `--coverage`. Upload to Codecov (codecov.io) for tracking. See: https://codecov.io');

        // 51. Container security scanning
        const containerScanTools = ['trivy', 'grype', 'docker scout', 'snyk container', 'anchore', 'clair', 'dockle'];
        const containerScanMatch = this._workflowIncludes(containerScanTools);
        const hasDockerfile = await checkFileExists(this.owner, this.repo, 'Dockerfile', this.token);
        this.addCheck(category, 'Container security scanning', containerScanMatch.found, 1,
            containerScanMatch.found
                ? `Container scanner "<strong>${containerScanMatch.kw}</strong>" in <a href="${containerScanMatch.url}" target="_blank" rel="noopener">${containerScanMatch.name}</a>`
                : hasDockerfile
                    ? `Dockerfile found but no container scanner configured. Checked for: ${containerScanTools.join(', ')}`
                    : `No Dockerfile found — container scanning not applicable`,
            'If using Docker, add image scanning to CI. Use Trivy (free, open source): add `- uses: aquasecurity/trivy-action@master` to your GitHub Actions workflow. See: https://github.com/aquasecurity/trivy-action');

        // 52. IaC security checks
        const iacScanTools = ['checkov', 'tfsec', 'terrascan', 'kics', 'infracost'];
        const iacScanMatch = this._workflowIncludes(iacScanTools);
        this.addCheck(category, 'IaC security checks', iacScanMatch.found, 1,
            iacScanMatch.found
                ? `IaC scanner "<strong>${iacScanMatch.kw}</strong>" in <a href="${iacScanMatch.url}" target="_blank" rel="noopener">${iacScanMatch.name}</a>`
                : `Checked ${this._workflowFiles.length} workflow(s) for: ${iacScanTools.join(', ')} — none found`,
            'If using Terraform/CloudFormation/Kubernetes IaC, add Checkov: `pip install checkov && checkov -d .`. GitHub Action: `bridgecrewio/checkov-action@master`. See: https://www.checkov.io/');

        // 53. Secure secrets management in CI
        const secretsMatch = this._workflowIncludes(['${{ secrets.']);
        this.addCheck(category, 'Secure secrets management in CI/CD', secretsMatch.found, 1,
            secretsMatch.found
                ? `Proper GitHub Secrets usage (<code>${'${{ secrets.… }}'}</code>) in <a href="${secretsMatch.url}" target="_blank" rel="noopener">${secretsMatch.name}</a>`
                : `Checked ${this._workflowFiles.length} workflow file(s) for <code>${'${{ secrets.… }}'}</code> — not found`,
            'Store all secrets as GitHub Secrets (Settings > Secrets and Variables > Actions). Reference them as `${{ secrets.MY_SECRET }}` in workflows. Never hardcode API keys or tokens in workflow files.');

        // 54. Environment configurations managed
        const envExampleCIResult = await checkFileExistsGetUrl(this.owner, this.repo, '.env.example', this.token);
        this.addCheck(category, 'Environment configurations managed', envExampleCIResult.exists, 1,
            envExampleCIResult.exists
                ? `Found <a href="${envExampleCIResult.url}" target="_blank" rel="noopener">.env.example</a>`
                : 'Checked for .env.example — not found',
            'Create .env.example documenting all required environment variables with placeholder values. Add .env to .gitignore. Use separate configs per environment (.env.development, .env.production).');

        // 55. Rollback mechanisms
        const rollbackMatch = this._workflowIncludes(['rollback', 'revert', 'helm rollback', 'blue-green', 'canary', 'undo']);
        this.addCheck(category, 'Rollback mechanisms available', rollbackMatch.found, 1,
            rollbackMatch.found
                ? `Found rollback mechanism "<strong>${rollbackMatch.kw}</strong>" in <a href="${rollbackMatch.url}" target="_blank" rel="noopener">${rollbackMatch.name}</a>`
                : `Checked ${this._workflowFiles.length} workflow(s) for rollback/revert/canary — none found`,
            'Implement rollback capabilities: tag each release (`git tag v1.0.0`), use blue-green deployments, or configure Helm rollback (`helm rollback <release>`). Document rollback procedures in RUNBOOK.md.');
    }

    async checkTesting() {
        const category = 'Testing & Validation';

        // Find test directories first
        const testDirNames = ['tests', 'test', '__tests__', 'spec'];
        let testDir = null;
        for (const d of testDirNames) {
            if (await checkDirectoryExists(this.owner, this.repo, d, this.token)) { testDir = d; break; }
        }
        const hasTests = testDir !== null;
        const testDirLink = testDir ? `<a href="${buildDirUrl(this.owner, this.repo, testDir)}" target="_blank" rel="noopener">${testDir}/</a>` : null;

        // Run all code-search-based tests in parallel to reduce latency
        const [edgeResult, mockResult, sanitizeResult, gracefulResult, regressionResult] = await Promise.all([
            hasTests ? searchCodeInRepo(this.owner, this.repo, 'edge_case OR boundary OR invalid_input', this.token)
                : Promise.resolve({ total_count: 0, items: [] }),
            hasTests ? searchCodeInRepo(this.owner, this.repo, 'mock OR stub OR MagicMock OR sinon', this.token)
                : Promise.resolve({ total_count: 0, items: [] }),
            hasTests ? searchCodeInRepo(this.owner, this.repo, 'sanitize OR xss OR injection OR sql_injection OR traversal', this.token)
                : Promise.resolve({ total_count: 0, items: [] }),
            searchCodeInRepo(this.owner, this.repo, 'except Exception OR catch (error) OR catch(err)', this.token),
            hasTests ? searchCodeInRepo(this.owner, this.repo, 'regression OR test_issue OR bug_fix OR repro', this.token)
                : Promise.resolve({ total_count: 0, items: [] }),
        ]);

        // 56. Tests cover edge cases
        let edgeCaseDetails = '';
        let hasEdgeCases = false;
        if (hasTests) {
            hasEdgeCases = edgeResult.total_count > 0;
            if (hasEdgeCases) {
                const item = edgeResult.items[0];
                edgeCaseDetails = `Found edge case test patterns in <a href="${item.html_url}" target="_blank" rel="noopener">${item.name}</a> (searched: edge_case, boundary, invalid_input)`;
            } else {
                edgeCaseDetails = `${testDirLink} exists but no edge_case/boundary test patterns found via code search`;
            }
        } else {
            edgeCaseDetails = `No test directory found — checked: ${testDirNames.join(', ')}`;
        }
        this.addCheck(category, 'Tests cover edge cases', hasEdgeCases, 1, edgeCaseDetails,
            'Write tests for boundary conditions: empty inputs, maximum values, null/undefined, invalid formats, and off-by-one errors. Use parameterised tests to cover many edge cases efficiently.');

        // 57. Unit + integration + E2E
        const intDirNames = ['integration', 'e2e', 'integration_tests', 'functional'];
        let intDir = null;
        for (const d of intDirNames) {
            if (await checkDirectoryExists(this.owner, this.repo, d, this.token)) { intDir = d; break; }
        }
        const hasIntTests = intDir !== null;
        this.addCheck(category, 'Unit, integration, and E2E tests', hasTests && hasIntTests, 1,
            `Unit tests: ${testDir ? testDirLink : 'not found'}; Integration/E2E: ${intDir ? `<a href="${buildDirUrl(this.owner, this.repo, intDir)}" target="_blank" rel="noopener">${intDir}/</a>` : 'not found'}`,
            'Implement a testing pyramid: many unit tests, some integration tests (API/DB), few E2E tests. Create separate directories: tests/unit/, tests/integration/, tests/e2e/.');

        // 58. Mocks and stubs
        let mocksDetails = '';
        const hasMocks = hasTests && mockResult.total_count > 0;
        if (hasTests) {
            if (hasMocks) {
                const item = mockResult.items[0];
                mocksDetails = `Found mock/stub patterns in <a href="${item.html_url}" target="_blank" rel="noopener">${item.name}</a>`;
            } else {
                mocksDetails = `${testDirLink} exists but no mock/stub patterns found (searched: mock, stub, MagicMock, sinon)`;
            }
        } else {
            mocksDetails = 'No test directory found';
        }
        this.addCheck(category, 'Uses mocks and stubs', hasMocks, 1, mocksDetails,
            'Use mocking frameworks to isolate units under test: unittest.mock for Python, Jest mocks for JS, Mockito for Java. Mock external services, databases, and APIs to make tests fast and deterministic.');

        // 59. 80%+ coverage — check for coverage config file
        const covCandidates = ['.coveragerc', '.nycrc', '.nycrc.json', 'jest.config.js', 'jest.config.ts', 'jest.config.json', 'codecov.yml'];
        let covFileResult = null;
        for (const cf of covCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, cf, this.token);
            if (r.exists) { covFileResult = { path: cf, url: r.url }; break; }
        }
        this.addCheck(category, 'Achieves 80%+ test coverage', covFileResult !== null, 1,
            covFileResult !== null
                ? `Found coverage config: <a href="${covFileResult.url}" target="_blank" rel="noopener">${covFileResult.path}</a>`
                : `Checked for: ${covCandidates.join(', ')} — none found`,
            'Set up and enforce coverage thresholds. For Python: `pytest --cov=src --cov-fail-under=80`. For Node.js: add `"coverageThreshold": {"global": {"lines": 80}}` in jest.config.json. Report to Codecov or Coveralls.');

        // 60. Tests validate input sanitization
        let sanitizeDetails = '';
        const hasSanitizeTests = hasTests && sanitizeResult.total_count > 0;
        if (hasTests) {
            if (hasSanitizeTests) {
                const item = sanitizeResult.items[0];
                sanitizeDetails = `Found security test patterns in <a href="${item.html_url}" target="_blank" rel="noopener">${item.name}</a>`;
            } else {
                sanitizeDetails = `${testDirLink} found but no sanitize/xss/injection test patterns detected`;
            }
        } else {
            sanitizeDetails = 'No test directory found';
        }
        this.addCheck(category, 'Tests validate input sanitization', hasSanitizeTests, 1, sanitizeDetails,
            'Write security-focused tests: test XSS payloads, SQL injection strings, path traversal, and other malicious inputs to verify they are properly rejected or sanitised.');

        // 61. Fuzz testing — search deps for fuzz testing libraries
        const fuzzKw = ['hypothesis', 'atheris', 'cargo-fuzz', 'go-fuzz', 'jazzer', 'pythonfuzz', 'libfuzzer'];
        const fuzzMatch = this._depsInclude(fuzzKw);
        this.addCheck(category, 'Automated fuzz testing', fuzzMatch.found, 1,
            fuzzMatch.found
                ? `Found fuzz testing library "<strong>${fuzzMatch.kw}</strong>" in <a href="${fuzzMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for fuzz testing: ${fuzzKw.join(', ')} — none found`,
            'Add fuzz testing for critical parsing code. For Python: `pip install hypothesis` or `atheris`. For Go: use built-in `go test -fuzz=FuzzMyFunc`. For Java: use Jazzer. Target input parsers, deserialisers, and cryptographic operations.');

        // 62. Graceful failure — results already fetched in parallel above
        const hasGracefulFailure = gracefulResult.total_count > 0;
        let gracefulDetails = '';
        if (hasGracefulFailure) {
            const item = gracefulResult.items[0];
            gracefulDetails = `Found error handling patterns in <a href="${item.html_url}" target="_blank" rel="noopener">${item.name}</a>`;
        } else {
            gracefulDetails = 'No error handling patterns found via code search';
        }
        this.addCheck(category, 'Fails gracefully with error logging', hasGracefulFailure, 1, gracefulDetails,
            'Implement proper error handling throughout the codebase. Use try/catch, handle expected exceptions, log errors with context (stack trace, user ID, request ID), and return meaningful error messages. Never expose raw stack traces in production.');

        // 63. No sensitive data in logs — check for log sanitisation in deps
        const logSanitiseKw = ['python-json-logger', 'structlog', 'redact', 'scrubber', 'log-sanitizer'];
        const logSanitiseMatch = this._depsInclude(logSanitiseKw);
        this.addCheck(category, 'No sensitive data in logs', logSanitiseMatch.found, 1,
            logSanitiseMatch.found
                ? `Found log sanitisation library "<strong>${logSanitiseMatch.kw}</strong>" in <a href="${logSanitiseMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Checked dependency files for log sanitisation libraries — none found (manual code review recommended)`,
            'Ensure sensitive data is never logged: passwords, tokens, PII, card numbers. Use a log sanitiser or custom formatter with a deny-list for sensitive fields. Audit log statements before each release.');

        // 64. Dependency injection — check deps for DI frameworks
        const diKw = ['dependency-injector', 'injector', 'spring', 'inversify', 'tsyringe', 'pinject', 'lagom', 'angular'];
        const diMatch = this._depsInclude(diKw);
        this.addCheck(category, 'Uses dependency injection', diMatch.found, 1,
            diMatch.found
                ? `Found DI library "<strong>${diMatch.kw}</strong>" in <a href="${diMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for DI frameworks: ${diKw.join(', ')} — none found`,
            'Implement dependency injection to improve testability: pass dependencies (DB, config, services) into constructors rather than creating them inside classes. Use a DI framework (Spring for Java, Angular DI, InversifyJS for TS/JS, dependency-injector for Python).');

        // 65. Regression tests — results already fetched in parallel above
        let regressionDetails = '';
        const hasRegression = hasTests && regressionResult.total_count > 0;
        if (hasTests) {
            if (hasRegression) {
                const item = regressionResult.items[0];
                regressionDetails = `Found regression test patterns in <a href="${item.html_url}" target="_blank" rel="noopener">${item.name}</a>`;
            } else {
                regressionDetails = `${testDirLink} exists — no explicit regression test patterns found`;
            }
        } else {
            regressionDetails = 'No test directory found';
        }
        this.addCheck(category, 'Regression tests for compatibility', hasRegression, 1, regressionDetails,
            'Write a regression test every time you fix a bug: create a test that reproduces the bug first, then fix it. Name them descriptively: `test_issue_123_login_fails_with_valid_credentials`. This prevents regressions from re-appearing.');
    }

    async checkPerformance() {
        const category = 'Performance & Scalability';

        // 66. Async processing — check deps for async libraries
        const asyncKw = ['asyncio', 'aiohttp', 'fastapi', 'trio', 'celery', 'rq', 'bullmq', 'rxjs', 'rxjava', 'reactor', 'asyncpg', 'httpx'];
        const asyncMatch = this._depsInclude(asyncKw);
        this.addCheck(category, 'Asynchronous processing where needed', asyncMatch.found, 1,
            asyncMatch.found
                ? `Found async library "<strong>${asyncMatch.kw}</strong>" in <a href="${asyncMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for async libraries: ${asyncKw.join(', ')} — none found`,
            'Use async processing for I/O-bound operations: in Python use asyncio/aiohttp, in Node.js use async/await, in Java use CompletableFuture or Spring WebFlux. Use task queues (Celery, BullMQ) for long-running background jobs.');

        // 67. Caching — check deps for cache libraries
        const cacheKw = ['redis', 'memcached', 'pylibmc', 'django-cache', 'flask-caching', 'node-cache', 'ioredis', 'lru-cache', 'caffeine', 'ehcache', 'varnish'];
        const cacheMatch = this._depsInclude(cacheKw);
        this.addCheck(category, 'Caching strategies implemented', cacheMatch.found, 1,
            cacheMatch.found
                ? `Found caching library "<strong>${cacheMatch.kw}</strong>" in <a href="${cacheMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for caching: ${cacheKw.join(', ')} — none found`,
            'Implement caching to reduce load: use Redis or Memcached for distributed caching, @lru_cache for function-level caching in Python, HTTP cache headers (ETag, Cache-Control) for API responses. Start with frequently read, infrequently changed data.');

        // 68. Optimised DB queries — check deps for ORM + index-related tools
        const dbOptKw = ['sqlalchemy', 'django-orm', 'prisma', 'typeorm', 'hibernate', 'sequelize', 'django.db', 'redis', 'elasticsearch', 'alembic', 'flyway'];
        const dbOptMatch = this._depsInclude(dbOptKw);
        this.addCheck(category, 'Optimized database queries', dbOptMatch.found, 1,
            dbOptMatch.found
                ? `Found DB/ORM library "<strong>${dbOptMatch.kw}</strong>" in <a href="${dbOptMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for DB/ORM libraries — none found`,
            'Optimise database queries: use `select_related`/`prefetch_related` (Django), eager loading (Rails/Hibernate), add indexes on frequently queried columns. Use EXPLAIN ANALYZE to identify slow queries. Avoid the N+1 query problem.');

        // 69. Rate limiting — check deps
        const rateLimitKw = ['django-ratelimit', 'flask-limiter', 'slowapi', 'express-rate-limit', 'rate-limiter-flexible', 'throttler', 'resilience4j', 'bucket4j'];
        const rateLimitMatch = this._depsInclude(rateLimitKw);
        this.addCheck(category, 'Rate limiting to prevent abuse', rateLimitMatch.found, 1,
            rateLimitMatch.found
                ? `Found rate limiting library "<strong>${rateLimitMatch.kw}</strong>" in <a href="${rateLimitMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for rate limiting: ${rateLimitKw.join(', ')} — none found`,
            'Implement rate limiting on all public-facing endpoints. For Express.js: `npm install express-rate-limit`. For Django: `pip install django-ratelimit`. For Flask: `pip install Flask-Limiter`. Set limits on auth endpoints (e.g., 5 attempts/15 minutes).');

        // 70. Performance optimisation — check deps for profiling/perf tools
        const perfKw = ['py-spy', 'memory-profiler', 'scalene', 'clinic', 'pprof', 'profiler', 'datadog', 'newrelic', 'dynatrace', 'pyinstrument'];
        const perfMatch = this._depsInclude(perfKw);
        this.addCheck(category, 'Code optimized for performance', perfMatch.found, 1,
            perfMatch.found
                ? `Found performance tool "<strong>${perfMatch.kw}</strong>" in <a href="${perfMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for profiling/performance tools — none found`,
            'Profile your application to find bottlenecks: use py-spy or Scalene for Python, clinic.js for Node.js, async-profiler for Java. Measure before and after optimising. Use appropriate data structures (dict for O(1) lookups).');

        // 71. No memory leaks — check deps for memory/leak detection tools
        const memKw = ['tracemalloc', 'objgraph', 'memory-profiler', 'memwatch-next', 'heapdump', 'node-memwatch', 'valgrind'];
        const memMatch = this._depsInclude(memKw);
        this.addCheck(category, 'No memory leaks', memMatch.found, 1,
            memMatch.found
                ? `Found memory tool "<strong>${memMatch.kw}</strong>" in <a href="${memMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for memory profiling tools — none found`,
            'Prevent memory leaks: use context managers (with) for resources, close DB connections explicitly, remove event listeners when done. Use tracemalloc (Python) or Chrome DevTools (JS) to profile memory usage. Test for leaks in long-running operations.');

        // 72. Load testing — check for load test config files
        const loadTestCandidates = ['k6.js', 'locustfile.py', 'artillery.yml', 'artillery.yaml', 'gatling.conf', 'jmeter.jmx'];
        let loadTestFile = null;
        for (const lt of loadTestCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, lt, this.token);
            if (r.exists) { loadTestFile = { path: lt, url: r.url }; break; }
        }
        const loadTestKw = ['k6', 'locust', 'artillery', 'gatling', 'jmeter', 'siege', 'vegeta'];
        const loadTestInDeps = this._depsInclude(loadTestKw);
        const hasLoadTest = loadTestFile !== null || loadTestInDeps.found;
        this.addCheck(category, 'Load testing performed', hasLoadTest, 1,
            hasLoadTest
                ? (loadTestFile
                    ? `Found load test config: <a href="${loadTestFile.url}" target="_blank" rel="noopener">${loadTestFile.path}</a>`
                    : `Found load testing tool "<strong>${loadTestInDeps.kw}</strong>" in <a href="${loadTestInDeps.url}" target="_blank" rel="noopener">dependency file</a>`)
                : `Checked for load test configs: ${loadTestCandidates.join(', ')} and load testing deps — none found`,
            'Set up load testing: use k6 (k6.io) or Locust (Python). Write scenarios simulating realistic traffic. Test before major releases. Target P95 response time under 500ms. Run load tests in CI on a schedule.');

        // 73. Horizontal scaling — check for Docker/Kubernetes files/dirs (explicit lists, no magic indices)
        const scalingFileCandidates = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'];
        const scalingDirCandidates = ['kubernetes', 'k8s', 'helm'];
        let scalingFile = null;
        for (const sf of scalingFileCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, sf, this.token);
            if (r.exists) { scalingFile = { path: sf, url: r.url }; break; }
        }
        if (!scalingFile) {
            for (const sd of scalingDirCandidates) {
                if (await checkDirectoryExists(this.owner, this.repo, sd, this.token)) {
                    scalingFile = { path: sd, url: buildDirUrl(this.owner, this.repo, sd) };
                    break;
                }
            }
        }
        const hasHorizScaling = scalingFile !== null;
        this.addCheck(category, 'Supports horizontal scaling', hasHorizScaling, 1,
            hasHorizScaling
                ? `Found <a href="${scalingFile.url}" target="_blank" rel="noopener">${scalingFile.path}</a> (enables containerised/horizontal scaling)`
                : `Checked for: ${[...scalingFileCandidates, ...scalingDirCandidates].join(', ')} — none found`,
            'Design for horizontal scaling: containerise with Docker, use Kubernetes for orchestration, make the app stateless. Store session state in Redis rather than in-process memory. Avoid hardcoded hostnames.');

        // 74. Lazy loading — search deps for lazy-load patterns
        const lazyKw = ['lazyload', 'react.lazy', 'dynamic import', 'loadable-components', 'lazy_import', 'importlib', 'werkzeug.local'];
        const lazyMatch = this._depsInclude(lazyKw);
        this.addCheck(category, 'Uses lazy loading', lazyMatch.found, 1,
            lazyMatch.found
                ? `Found lazy loading library "<strong>${lazyMatch.kw}</strong>" in <a href="${lazyMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for lazy loading patterns — none found`,
            'Implement lazy loading where appropriate: dynamic import() for code splitting in JS/TS, React.lazy() for components, @lru_cache for expensive computations. Lazy load images and non-critical resources.');

        // 75. Pagination — check deps for pagination libraries
        const paginationKw = ['django-rest-framework', 'flask-sqlalchemy', 'paginate', 'pagination', 'cursor-pagination', 'relay-cursor', 'spring-data', 'paginator'];
        const paginationMatch = this._depsInclude(paginationKw);
        this.addCheck(category, 'Pagination for large datasets', paginationMatch.found, 1,
            paginationMatch.found
                ? `Found pagination library "<strong>${paginationMatch.kw}</strong>" in <a href="${paginationMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for pagination support — none found`,
            'Implement pagination for all list endpoints. Never return unbounded lists. Set a default page size (e.g., 25) and a maximum (e.g., 100). Use cursor-based pagination for real-time data. Example: `?page=2&per_page=25`');
    }

    async checkLogging() {
        const category = 'Logging & Monitoring';

        // 76. Logging implemented — check deps for logging libraries
        const logKw = ['winston', 'pino', 'bunyan', 'morgan', 'log4j', 'logback', 'slf4j', 'loguru', 'structlog', 'python-json-logger', 'zap', 'slog', 'zerolog', 'serilog', 'nlog'];
        const logMatch = this._depsInclude(logKw);
        this.addCheck(category, 'Logging implemented', logMatch.found, 1,
            logMatch.found
                ? `Found logging library "<strong>${logMatch.kw}</strong>" in <a href="${logMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for logging frameworks: ${logKw.join(', ')} — none found`,
            'Add structured logging to your application. For Python: `pip install loguru` or use stdlib logging. For Node.js: `npm install winston pino`. For Java: use SLF4J with Logback. Log all significant events, errors, and security actions.');

        // 77. Configurable log levels — check .env.example for LOG_LEVEL or known log-level deps
        const logLevelInDeps = this._depsInclude(['log-level', 'loglevel', 'LOG_LEVEL']);
        const envExLogResult = await checkFileExistsGetUrl(this.owner, this.repo, '.env.example', this.token);
        let envExContent = null;
        if (envExLogResult.exists) {
            envExContent = await getFileContentAndUrl(this.owner, this.repo, '.env.example', this.token);
        }
        const logLevelInEnvEx = envExContent && envExContent.content.toLowerCase().includes('log_level');
        const hasLogLevels = logLevelInDeps.found || logLevelInEnvEx || logMatch.found;
        this.addCheck(category, 'Configurable log levels', hasLogLevels, 1,
            hasLogLevels
                ? (logLevelInEnvEx
                    ? `LOG_LEVEL found in <a href="${envExContent.url}" target="_blank" rel="noopener">.env.example</a>`
                    : logLevelInDeps.found
                        ? `Log level config in <a href="${logLevelInDeps.url}" target="_blank" rel="noopener">dependency file</a>`
                        : `Logging library "<strong>${logMatch.kw}</strong>" supports configurable log levels`)
                : 'No LOG_LEVEL configuration or log level settings found',
            'Configure log levels via environment variables: `LOG_LEVEL=DEBUG` for development, `LOG_LEVEL=WARNING` for production. This lets you change verbosity without code deployments.');

        // 78. Logs don't contain sensitive data — check for log sanitisation libs
        const logSanitKw = ['python-json-logger', 'structlog', 'pii-safe-logging', 'log-redactor', 'scrubber'];
        const logSanitMatch = this._depsInclude(logSanitKw);
        this.addCheck(category, 'Logs don\'t contain sensitive data', logSanitMatch.found, 1,
            logSanitMatch.found
                ? `Found log sanitisation library "<strong>${logSanitMatch.kw}</strong>" in <a href="${logSanitMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : 'No log sanitisation library detected — manual code review needed to verify sensitive data is not logged',
            'Audit log statements for sensitive data: passwords, tokens, credit cards, SSNs, PII. Implement a log sanitiser or custom formatter. Use allowlists rather than denylists for fields that may be logged.');

        // 79. Monitoring integration — check deps for monitoring/observability tools
        const monitorKw = ['sentry-sdk', 'sentry', 'datadog', 'newrelic', 'prometheus-client', 'grafana', 'opentelemetry', 'jaeger', 'zipkin', 'statsd', 'elastic-apm', 'dynatrace'];
        const monitorMatch = this._depsInclude(monitorKw);
        this.addCheck(category, 'Monitoring integration', monitorMatch.found, 1,
            monitorMatch.found
                ? `Found monitoring library "<strong>${monitorMatch.kw}</strong>" in <a href="${monitorMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for monitoring tools: ${monitorKw.join(', ')} — none found`,
            'Set up monitoring: use Sentry (free tier) for error tracking, Prometheus+Grafana for metrics, or Datadog/New Relic for APM. At minimum, add error alerting so you know when things break in production.');

        // 80. Structured logging — check deps for structured/JSON logging
        const structLogKw = ['structlog', 'python-json-logger', 'pino', 'bunyan', 'winston', 'zerolog', 'zap', 'serilog', 'logstash-logback'];
        const structMatch = this._depsInclude(structLogKw);
        this.addCheck(category, 'Structured logging format', structMatch.found, 1,
            structMatch.found
                ? `Found structured logging library "<strong>${structMatch.kw}</strong>" in <a href="${structMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for structured logging — none found`,
            'Use structured (JSON) logging: `{"timestamp":"…","level":"INFO","message":"…","user_id":123}`. For Python: `pip install python-json-logger`. For Node.js: use Pino or Winston with JSON format. JSON logs are machine-parseable and integrate with log aggregation tools.');

        // 81. Audit logs — check deps for audit log libraries
        const auditKw = ['django-auditlog', 'django-simple-history', 'python-audit-log', 'audit-log', 'papertrail', 'activitypub'];
        const auditMatch = this._depsInclude(auditKw);
        this.addCheck(category, 'Audit logs for security actions', auditMatch.found, 1,
            auditMatch.found
                ? `Found audit log library "<strong>${auditMatch.kw}</strong>" in <a href="${auditMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for audit logging: ${auditKw.join(', ')} — none found`,
            'Implement audit logging for security-sensitive operations: logins, permission changes, data exports, deletions. Log who, what, when, and from where. Store audit logs separately with longer retention than application logs.');

        // 82. Alerts configured — check deps for alerting tools
        const alertKw = ['pagerduty', 'opsgenie', 'victorops', 'alertmanager', 'sentry-sdk', 'pingdom', 'uptimerobot'];
        const alertMatch = this._depsInclude(alertKw);
        const alertFileResult = await checkFileExistsGetUrl(this.owner, this.repo, 'alertmanager.yml', this.token);
        const hasAlerts = alertMatch.found || alertFileResult.exists;
        this.addCheck(category, 'Alerts configured', hasAlerts, 1,
            hasAlerts
                ? (alertFileResult.exists
                    ? `Found <a href="${alertFileResult.url}" target="_blank" rel="noopener">alertmanager.yml</a>`
                    : `Found alerting tool "<strong>${alertMatch.kw}</strong>" in <a href="${alertMatch.url}" target="_blank" rel="noopener">dependency file</a>`)
                : `Searched dependency files for alerting tools and alertmanager.yml — none found`,
            'Set up alerting: use Sentry (free tier) for error alerts, configure uptime monitoring with UptimeRobot (free), add alerting rules in Prometheus/Grafana. Ensure critical failures wake someone up, not just get silently logged.');

        // 83. Log rotation — check deps for log rotation
        const logRotKw = ['logrotate', 'RotatingFileHandler', 'TimedRotatingFileHandler', 'winston-daily-rotate-file', 'log4j-rolling', 'logback-rolling'];
        const logRotMatch = this._depsInclude(logRotKw);
        this.addCheck(category, 'Log rotation and archival', logRotMatch.found, 1,
            logRotMatch.found
                ? `Found log rotation library "<strong>${logRotMatch.kw}</strong>" in <a href="${logRotMatch.url}" target="_blank" rel="noopener">dependency file</a>`
                : `Searched dependency files for log rotation — none found`,
            'Configure log rotation to prevent disk exhaustion: use Python\'s RotatingFileHandler (maxBytes, backupCount), winston-daily-rotate-file for Node.js, or use cloud logging (CloudWatch, Stackdriver) with auto-expiry policies.');

        // 84. Incident response playbook — check for runbook/playbook files
        const playbookCandidates = ['RUNBOOK.md', 'runbook.md', 'INCIDENT.md', 'incident-response.md', 'PLAYBOOK.md', 'playbook.md', 'ON_CALL.md', 'docs/runbook.md', 'docs/incident.md'];
        let playbookResult = null;
        for (const pf of playbookCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, pf, this.token);
            if (r.exists) { playbookResult = { path: pf, url: r.url }; break; }
        }
        this.addCheck(category, 'Incident response playbook', playbookResult !== null, 1,
            playbookResult !== null
                ? `Found <a href="${playbookResult.url}" target="_blank" rel="noopener">${playbookResult.path}</a>`
                : `Checked for: ${playbookCandidates.join(', ')} — none found`,
            'Create a RUNBOOK.md or INCIDENT.md documenting: how to diagnose common issues, on-call contacts, escalation paths, rollback procedures, and post-mortem template. Essential for on-call engineers and disaster recovery.');

        // 85. Logging config separate from code — check for dedicated config files
        const logConfigCandidates = ['logging.yml', 'logging.yaml', 'logging.json', 'log4j2.xml', 'logback.xml', 'log.conf', 'logging.conf'];
        let logConfigResult = null;
        for (const lc of logConfigCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, lc, this.token);
            if (r.exists) { logConfigResult = { path: lc, url: r.url }; break; }
        }
        this.addCheck(category, 'Logging config separate from code', logConfigResult !== null, 1,
            logConfigResult !== null
                ? `Found <a href="${logConfigResult.url}" target="_blank" rel="noopener">${logConfigResult.path}</a>`
                : `Checked for: ${logConfigCandidates.join(', ')} — none found`,
            'Store logging configuration outside code: use a logging.yml or logging.json file, or configure via environment variables (LOG_LEVEL, LOG_FORMAT). This allows changing verbosity in production without code deployments.');
    }

    async checkCommunity() {
        const category = 'Community & Support';

        // 86. Active maintainers
        const pushedAt = new Date(this.repoData.pushed_at);
        const oneYearAgo = new Date();
        oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
        const recentlyUpdated = pushedAt > oneYearAgo;
        this.addCheck(category, 'Maintainers actively engage', recentlyUpdated, 1,
            `GitHub API <code>pushed_at</code>: <strong>${pushedAt.toLocaleDateString()}</strong> — ${recentlyUpdated ? 'within the last year' : 'more than a year ago'}`,
            'Actively maintain the project: respond to issues and PRs within 2 weeks. If inactive, add a maintenance status badge to the README. Consider archiving if no longer maintained.');

        // 87-88. Security reporting
        const commSecResult = await checkFileExistsGetUrl(this.owner, this.repo, 'SECURITY.md', this.token);
        this.addCheck(category, 'Security vulnerability reporting process', commSecResult.exists, 1,
            commSecResult.exists
                ? `Found <a href="${commSecResult.url}" target="_blank" rel="noopener">SECURITY.md</a>`
                : 'Checked for SECURITY.md — not found',
            'Create SECURITY.md with your vulnerability disclosure process: how to report (private email / GitHub private reporting), response time commitment, and supported versions.');
        this.addCheck(category, 'Security policy file (SECURITY.md)', commSecResult.exists, 1,
            commSecResult.exists
                ? `<a href="${commSecResult.url}" target="_blank" rel="noopener">SECURITY.md</a> present`
                : 'SECURITY.md not found — checked via GitHub API /contents/SECURITY.md',
            'Create SECURITY.md. Use GitHub\'s template: Security tab > Policy > Enable private vulnerability reporting. This is required for OWASP projects.');

        // 89. Community guidelines (CODE_OF_CONDUCT.md)
        const commCocResult = await checkFileExistsGetUrl(this.owner, this.repo, 'CODE_OF_CONDUCT.md', this.token);
        this.addCheck(category, 'Community guidelines present', commCocResult.exists, 1,
            commCocResult.exists
                ? `Found <a href="${commCocResult.url}" target="_blank" rel="noopener">CODE_OF_CONDUCT.md</a>`
                : 'Checked for CODE_OF_CONDUCT.md — not found',
            'Add CODE_OF_CONDUCT.md: use the Contributor Covenant template (contributor-covenant.org). This is required for OWASP projects and fosters a welcoming community.');

        // 90. Responsive to security issues
        this.addCheck(category, 'Responsive to security issues', commSecResult.exists, 1,
            commSecResult.exists
                ? `<a href="${commSecResult.url}" target="_blank" rel="noopener">SECURITY.md</a> documents the security response process`
                : 'No security policy found — responsiveness cannot be verified',
            'Define a security response SLA: acknowledge reports within 24–48 hours, provide a fix timeline (e.g., 90 days for critical issues). Enable GitHub private vulnerability reporting under the Security tab.');

        // 91. Regular project updates
        this.addCheck(category, 'Regular project updates', recentlyUpdated, 1,
            `GitHub API <code>pushed_at</code>: <strong>${pushedAt.toLocaleDateString()}</strong>`,
            'Maintain regular activity on the project. If on a planned pause, document it in the README. Respond to opened issues and PRs even if major development is paused.');

        // 92. Multiple support channels
        const hasDiscussions = this.repoData.has_discussions;
        this.addCheck(category, 'Multiple support channels', hasDiscussions, 1,
            `GitHub API <code>has_discussions</code>: <strong>${hasDiscussions}</strong>`,
            'Enable GitHub Discussions (Settings > Discussions) for community Q&A. Link to other support channels (Slack, Discord, mailing list) in the README. Multiple channels increase project accessibility.');

        // 93. Clear escalation path
        this.addCheck(category, 'Clear escalation path', commSecResult.exists, 1,
            commSecResult.exists
                ? `Escalation path documented in <a href="${commSecResult.url}" target="_blank" rel="noopener">SECURITY.md</a>`
                : 'No escalation path found — SECURITY.md not present',
            'Document an escalation path: who to contact for critical issues, response time commitment, and PGP key for encrypted reports. Include this in SECURITY.md.');

        // 94. PR reviews before merging — check branch protection
        const defaultBranch = this.repoData.default_branch || 'main';
        try {
            const branchData = await githubRequest(`/repos/${this.owner}/${this.repo}/branches/${defaultBranch}`, this.token);
            const hasProtection = branchData.protected === true;
            this.addCheck(category, 'PR reviews before merging', hasProtection, 1,
                `Default branch "<strong>${defaultBranch}</strong>" — <code>protected</code>: <strong>${branchData.protected}</strong> (checked via GitHub API /branches/${defaultBranch})`,
                'Enable branch protection: Settings > Branches > Add rule. Require at least 1 PR review, require status checks to pass, dismiss stale reviews, and disallow direct pushes to main/master.');
        } catch {
            this.addCheck(category, 'PR reviews before merging', false, 1,
                'Could not check branch protection (may require an authenticated token)',
                'Enable branch protection: Settings > Branches > Add branch protection rule. Require PR reviews and passing CI status checks before merging.');
        }

        // 95. Good issue tracking hygiene
        const hasIssues = this.repoData.has_issues;
        const openIssues = this.repoData.open_issues_count;
        this.addCheck(category, 'Good issue tracking hygiene', hasIssues, 1,
            `GitHub API — Issues enabled: <strong>${hasIssues}</strong>, open issues: <strong>${openIssues}</strong>`,
            'Use GitHub Issues effectively: create issue templates (.github/ISSUE_TEMPLATE/), add labels (bug, enhancement, security), set milestones, and regularly triage open issues. Respond to issues within 2 weeks.');
    }

    async checkLegal() {
        const category = 'Legal & Compliance';

        // 96. GDPR/CCPA — check for privacy policy file or README mention
        const privacyCandidates = ['PRIVACY.md', 'PRIVACY_POLICY.md', 'privacy-policy.md', 'PRIVACY.txt'];
        let privacyResult = null;
        for (const pf of privacyCandidates) {
            const r = await checkFileExistsGetUrl(this.owner, this.repo, pf, this.token);
            if (r.exists) { privacyResult = { path: pf, url: r.url }; break; }
        }
        const privacyInReadme = this._readme && (this._readme.includes('gdpr') || this._readme.includes('privacy') || this._readme.includes('ccpa') || this._readme.includes('data collection'));
        const hasPrivacy = privacyResult !== null || privacyInReadme;
        this.addCheck(category, 'GDPR/CCPA compliance', hasPrivacy, 1,
            hasPrivacy
                ? (privacyResult
                    ? `Found <a href="${privacyResult.url}" target="_blank" rel="noopener">${privacyResult.path}</a>`
                    : `README mentions privacy/GDPR — <a href="${buildFileUrl(this.owner, this.repo, 'README.md')}" target="_blank" rel="noopener">view README</a>`)
                : `Checked for: ${privacyCandidates.join(', ')} and README privacy mentions — none found`,
            'If your project collects or processes personal data, create a PRIVACY.md documenting: what data you collect, why, retention period, and how users can request deletion (GDPR Art. 13/14). If no data is collected, state this explicitly in the README.');

        // 97. Dependencies properly licensed
        const hasLicense = this.repoData.license !== null;
        const licUrl = hasLicense ? `https://github.com/${this.owner}/${this.repo}/blob/main/LICENSE` : null;
        this.addCheck(category, 'Dependencies properly licensed', hasLicense, 1,
            hasLicense
                ? `Project license: <a href="${licUrl}" target="_blank" rel="noopener">${this.repoData.license.name}</a> — detected via GitHub API <code>repo.license</code>`
                : 'No license detected in GitHub repository metadata',
            'Add a LICENSE file and audit third-party dependency licenses. Run `pip-licenses` for Python or `npx license-checker` for Node.js. Avoid GPL in commercial projects without understanding the implications.');

        // 98. No proprietary/restricted code
        this.addCheck(category, 'No proprietary/restricted code', hasLicense, 1,
            hasLicense
                ? `Open-source license: <strong>${this.repoData.license.name}</strong> — detected via GitHub API`
                : 'No license file found — proprietary status is unclear',
            'Ensure all code in the repository uses an OSI-approved open-source license. Review third-party snippets for license compatibility. See: https://opensource.org/licenses');

        // 99. Users informed of data collection
        this.addCheck(category, 'Users informed of data collection', hasPrivacy, 1,
            hasPrivacy
                ? (privacyResult
                    ? `Privacy policy: <a href="${privacyResult.url}" target="_blank" rel="noopener">${privacyResult.path}</a>`
                    : `README contains privacy information — <a href="${buildFileUrl(this.owner, this.repo, 'README.md')}" target="_blank" rel="noopener">view README</a>`)
                : `No dedicated privacy notice found — checked for ${privacyCandidates.join(', ')} and README`,
            'Be transparent about data collection: create PRIVACY.md or add a Privacy section to README. State clearly what data (if any) is collected, why it\'s needed, how it\'s stored, and how users can opt out.');

        // 100. Responsible disclosure policy
        const legalSecResult = await checkFileExistsGetUrl(this.owner, this.repo, 'SECURITY.md', this.token);
        this.addCheck(category, 'Responsible disclosure policy', legalSecResult.exists, 1,
            legalSecResult.exists
                ? `Found <a href="${legalSecResult.url}" target="_blank" rel="noopener">SECURITY.md</a> — checked via GitHub API /contents/SECURITY.md`
                : 'No SECURITY.md found',
            'Create a responsible disclosure policy in SECURITY.md: specify private reporting channels, a 90-day disclosure timeline, and the CVE/advisory process. Enable GitHub\'s private vulnerability reporting under the Security tab.');
    }

    async runAllChecks() {
        await this.fetchRepositoryData();
        // Pre-fetch shared data to minimise API calls
        await this.prefetchSharedData();
        await this.checkGeneralCompliance();
        await this.checkDocumentation();
        await this.checkCodeQuality();
        await this.checkSecurity();
        await this.checkCICD();
        await this.checkTesting();
        await this.checkPerformance();
        await this.checkLogging();
        await this.checkCommunity();
        await this.checkLegal();

        this.results.percentage = Math.round((this.results.score / this.results.maxScore) * 100);
        return this.results;
    }
}

// UI Functions
function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
}

function hideError() {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.classList.add('hidden');
}

function setLoading(isLoading) {
    const btn = document.getElementById('checkBtn');
    const btnText = document.getElementById('btnText');
    const spinner = document.getElementById('btnSpinner');
    const input = document.getElementById('repoUrl');

    btn.disabled = isLoading;
    input.disabled = isLoading;

    if (isLoading) {
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
    } else {
        btnText.classList.remove('hidden');
        spinner.classList.add('hidden');
    }
}

function escapeHtml(value) {
    if (value === null || value === undefined) {
        return '';
    }

    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

function displayResults(results) {
    currentResults = results;

    // Show results section
    document.getElementById('results').classList.remove('hidden');

    // Update repo info
    const repoInfoDiv = document.getElementById('repoInfo');
    repoInfoDiv.innerHTML = '';
    const span = document.createElement('span');
    span.className = 'inline-flex items-center gap-2';
    const icon = document.createElement('i');
    icon.className = 'fa-solid fa-folder-tree';
    icon.setAttribute('aria-hidden', 'true');
    const link = document.createElement('a');
    link.href = results.url;
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = results.url.replace('https://github.com/', '');
    span.appendChild(icon);
    span.appendChild(link);
    repoInfoDiv.appendChild(span);

    // Update score
    const percentage = results.percentage;
    document.getElementById('scoreValue').textContent = percentage;

    // Update score circle
    const circle = document.getElementById('scoreCircle');
    const circumference = 339.292;
    const offset = circumference - (percentage / 100) * circumference;
    circle.style.strokeDashoffset = offset;

    // Update score color and status
    let statusText = '';
    let statusColor = '';

    if (percentage >= 80) {
        statusText = 'EXCELLENT COMPLIANCE';
        statusColor = '#27ae60';
        circle.style.stroke = '#27ae60';
    } else if (percentage >= 60) {
        statusText = 'GOOD COMPLIANCE';
        statusColor = '#f39c12';
        circle.style.stroke = '#f39c12';
    } else if (percentage >= 40) {
        statusText = 'NEEDS IMPROVEMENT';
        statusColor = '#e67e22';
        circle.style.stroke = '#e67e22';
    } else {
        statusText = 'SIGNIFICANT IMPROVEMENTS NEEDED';
        statusColor = '#e74c3c';
        circle.style.stroke = '#e74c3c';
    }

    const scoreStatus = document.getElementById('scoreStatus');
    scoreStatus.textContent = statusText;
    scoreStatus.style.color = statusColor;

    document.getElementById('scorePoints').textContent =
        `${results.score} out of ${results.maxScore} points`;

    // Display categories
    const categoriesDiv = document.getElementById('categories');
    categoriesDiv.innerHTML = '';

    for (const [categoryName, categoryData] of Object.entries(results.categories)) {
        const categoryDiv = document.createElement('div');
        categoryDiv.className = 'category';

        const categoryPercentage = Math.round((categoryData.score / categoryData.maxScore) * 100);
        const safeCategoryName = escapeHtml(categoryName);

        categoryDiv.innerHTML = `
            <button type="button" class="category-header" onclick="toggleCategory(this)" aria-expanded="false">
                <div class="category-title">${safeCategoryName}</div>
                <div class="inline-flex items-center gap-3">
                    <div class="category-score">${categoryData.score}/${categoryData.maxScore} (${categoryPercentage}%)</div>
                    <i class="fa-solid fa-chevron-right category-chevron" aria-hidden="true"></i>
                </div>
            </button>
            <div class="category-content">
                <div class="checks-list">
                    ${categoryData.checks.map(check => {
            const safeName = escapeHtml(check.name);
            const safeDetails = escapeHtml(check.details);
            const safeHowToFix = escapeHtml(check.howToFix);

            return `
                        <div class="check-item">
                            <div class="check-icon ${check.passed ? 'passed' : 'failed'}">
                                <i class="fa-solid ${check.passed ? 'fa-circle-check' : 'fa-circle-xmark'}" aria-hidden="true"></i>
                            </div>
                            <div class="check-content">
                                <div class="check-name">${safeName}</div>
                                ${safeDetails ? `<div class="check-details">${safeDetails}</div>` : ''}
                                ${!check.passed && safeHowToFix ? `<div class="check-howtofix"><i class="fa-solid fa-circle-info" aria-hidden="true"></i> <strong>How to fix:</strong> ${safeHowToFix}</div>` : ''}
                            </div>
                            <div class="check-points">${check.points}/${check.maxPoints} pts</div>
                        </div>
                    `;
        }).join('')}
                </div>
            </div>
        `;

        categoriesDiv.appendChild(categoryDiv);
    }

    // Scroll to results
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toggleCategory(header) {
    const category = header.parentElement;
    const isExpanded = category.classList.toggle('expanded');
    header.setAttribute('aria-expanded', String(isExpanded));
}

// Main check compliance function
async function checkCompliance() {
    hideError();

    const repoUrl = document.getElementById('repoUrl').value.trim();
    const token = document.getElementById('githubToken').value.trim() || null;

    if (!repoUrl) {
        showError('Please enter a GitHub repository URL');
        return;
    }

    try {
        setLoading(true);

        // Clear the API cache so results from a previous run do not bleed into this one
        _apiCache.clear();

        // Parse URL
        const { owner, repo } = parseGitHubUrl(repoUrl);

        // Create checker and run checks
        const checker = new ComplianceChecker(owner, repo, token);
        const results = await checker.runAllChecks();

        // Display results
        displayResults(results);

    } catch (error) {
        showError(error.message);
        console.error('Compliance check error:', error);
    } finally {
        setLoading(false);
    }
}

// Allow Enter key to submit
document.addEventListener('DOMContentLoaded', () => {
    const repoInput = document.getElementById('repoUrl');
    const sampleRepoBtn = document.getElementById('sampleRepoBtn');
    const sidebarLinks = document.querySelectorAll('.sidebar-link');

    repoInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            checkCompliance();
        }
    });

    if (sampleRepoBtn) {
        sampleRepoBtn.addEventListener('click', () => {
            repoInput.value = 'https://github.com/OWASP/owasp-mastg';
            repoInput.focus();
        });
    }

    sidebarLinks.forEach((link) => {
        link.addEventListener('click', () => {
            sidebarLinks.forEach((item) => item.classList.remove('active'));
            if (link.getAttribute('href') && link.getAttribute('href').startsWith('#')) {
                link.classList.add('active');
            }
        });
    });
});
