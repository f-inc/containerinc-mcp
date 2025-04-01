import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import fs from 'fs/promises';
import path from 'path';
import { simpleGit, RemoteWithRefs } from 'simple-git';

interface GitHubDeviceResponse {
    device_code: string;
    user_code: string;
    verification_uri: string;
    expires_in: number;
    interval: number;
}

interface GitHubTokenResponse {
    access_token: string;
    token_type: string;
    scope: string;
}

interface StoredSession {
    githubToken?: string;
    lastUsed: number;
    pendingAuth?: {
        device_code: string;
        interval: number;
        expires_at: number;
    };
}

interface DeploymentResponse {
    id: string;
    trackingUrl: string;
}

interface DeployArguments {
    folder: string;
    repository: string;
    branch?: string;
}

class DeviceFlowServer {
    private server: Server;
    private tokenStorePath: string;
    private deploymentApiUrl: string;
    private githubClientId: string;

    constructor() {
        this.server = new Server(
            {
                name: '@container-inc/mcp',
                version: '1.0.0',
            },
            {
                capabilities: {
                    tools: {}
                }
            }
        );

        this.deploymentApiUrl = process.env.DEPLOYMENT_API_URL || 'https://container.inc';
        this.tokenStorePath = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.container-inc', 'session.json');
        this.githubClientId = process.env.GITHUB_CLIENT_ID || 'Ov23liPEmmIO16ie9OFJ';

        this.setupTools();
    }

    private async readSession(): Promise<StoredSession | null> {
        try {
            const data = await fs.readFile(this.tokenStorePath, 'utf-8');
            return JSON.parse(data);
        } catch (error) {
            return null;
        }
    }

    private async writeSession(session: StoredSession): Promise<void> {
        await fs.mkdir(path.dirname(this.tokenStorePath), { recursive: true });
        await fs.writeFile(this.tokenStorePath, JSON.stringify(session), 'utf-8');
    }

    private async getValidToken(): Promise<string | null> {
        const session = await this.readSession();
        if (!session?.githubToken) return null;
        
        // Check if token is still valid by making a test API call
        try {
            await axios.get('https://api.github.com/user', {
                headers: {
                    'Authorization': `Bearer ${session.githubToken}`,
                    'Accept': 'application/json'
                }
            });
        } catch (error) {
            return null;
        }
        
        return session.githubToken;
    }

    private async saveToken(token: string): Promise<void> {
        const session = await this.readSession() || { lastUsed: Date.now() };
        session.githubToken = token;
        session.lastUsed = Date.now();
        session.pendingAuth = undefined; // Clear any pending auth
        await this.writeSession(session);
    }

    private async savePendingAuth(deviceCode: string, interval: number, expiresIn: number): Promise<void> {
        const session = await this.readSession() || { lastUsed: Date.now() };
        session.pendingAuth = {
            device_code: deviceCode,
            interval,
            expires_at: Date.now() + (expiresIn * 1000)
        };
        await this.writeSession(session);
    }

    private async pollForToken(deviceCode: string, interval: number): Promise<string | null> {
        try {
            const response = await axios.post<GitHubTokenResponse>(
                'https://github.com/login/oauth/access_token',
                {
                    client_id: this.githubClientId,
                    device_code: deviceCode,
                    grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
                },
                {
                    headers: {
                        Accept: 'application/json'
                    }
                }
            );

            if (response.data.access_token) {
                return response.data.access_token;
            }
        } catch (error) {
            if (axios.isAxiosError(error) && error.response?.data?.error === 'authorization_pending') {
                // This is expected when the user hasn't completed the auth flow yet
                return null;
            }
            // For other errors, we should log them
            console.error('Error polling for token:', error);
            return null;
        }
        return null;
    }

    private async getCurrentUser(): Promise<string> {
        try {
            const response = await axios.get(
                'https://api.github.com/user',
                {
                    headers: {
                        Authorization: `Bearer ${await this.getValidToken()}`,
                        Accept: 'application/vnd.github.v3+json'
                    }
                }
            );
            return response.data.login;
        } catch (error) {
            throw new Error('Failed to get current user information');
        }
    }

    private async createGitHubRepo(repoName: string): Promise<string> {
        try {
            let owner: string;
            let repo: string;

            if (repoName.includes('/')) {
                // If owner/repo format is provided
                [owner, repo] = repoName.split('/');
                if (!owner || !repo) {
                    throw new Error('Repository must be in the format "owner/repository" or just "repository"');
                }
            } else {
                // If only repo name is provided, use current user as owner
                owner = await this.getCurrentUser();
                repo = repoName;
            }

            // Validate owner and repo names
            if (!/^[a-zA-Z0-9-_.]+$/.test(owner)) {
                throw new Error('Owner name can only contain alphanumeric characters, hyphens, underscores, and dots');
            }
            if (!/^[a-zA-Z0-9-_.]+$/.test(repo)) {
                throw new Error('Repository name can only contain alphanumeric characters, hyphens, underscores, and dots');
            }

            const fullRepoName = `${owner}/${repo}`;

            // Check if repository already exists
            try {
                const response = await axios.get(
                    `https://api.github.com/repos/${fullRepoName}`,
                    {
                        headers: {
                            Authorization: `Bearer ${await this.getValidToken()}`,
                            Accept: 'application/vnd.github.v3+json'
                        }
                    }
                );
                return response.data.clone_url;
            } catch (error) {
                if (axios.isAxiosError(error) && error.response?.status !== 404) {
                    throw error;
                }
            }

            // Create new repository
            const response = await axios.post(
                'https://api.github.com/user/repos',
                {
                    name: repo,
                    private: true,
                    auto_init: false
                },
                {
                    headers: {
                        Authorization: `Bearer ${await this.getValidToken()}`,
                        Accept: 'application/vnd.github.v3+json'
                    }
                }
            );

            return response.data.clone_url;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const errorMessage = error.response?.data?.message || 'Unknown GitHub API error';
                throw new Error(`Failed to create GitHub repository: ${errorMessage}`);
            }
            throw error;
        }
    }

    private async setupGitRepo(folder: string, repoUrl: string): Promise<void> {
        try {
            // Create a new Git instance for the specified folder
            const folderGit = simpleGit({ baseDir: folder });

            // Check if we're in a Git repository
            const isGitRepo = await folderGit.checkIsRepo();
            if (!isGitRepo) {
                // Initialize Git repository
                await folderGit.init();
                await folderGit.add('.');
                await folderGit.commit('Initial commit');
            }

            // Check if we have any remotes
            const remotes = await folderGit.getRemotes(true);
            const origin = remotes.find((remote: RemoteWithRefs) => remote.name === 'origin');

            if (origin) {
                // If origin exists, it must match the desired repository
                if (origin.refs.fetch !== repoUrl) {
                    throw new Error(`Repository remote origin (${origin.refs.fetch}) does not match desired repository (${repoUrl}). Please use the correct repository or remove the existing remote.`);
                }
            } else {
                // No origin exists, add it
                await folderGit.addRemote('origin', repoUrl);
            }
        } catch (error) {
            if (error instanceof Error) {
                throw error;
            }
            throw new Error('Failed to setup Git repository');
        }
    }

    private async deployToContainerInc(repoUrl: string): Promise<DeploymentResponse> {
        try {
            const response = await axios.post(
                `${this.deploymentApiUrl}/api/v1/deploy`,
                {
                    repository: repoUrl
                },
                {
                    headers: {
                        Authorization: `Bearer ${await this.getValidToken()}`,
                        'Content-Type': 'application/json'
                    }
                }
            );

            return response.data;
        } catch (error) {
            throw new Error('Failed to initiate deployment');
        }
    }

    private setupTools() {
        // List available tools
        this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
            tools: [
                {
                    name: 'start_auth',
                    description: 'Start the GitHub device flow authentication process',
                    inputSchema: {
                        type: 'object',
                        properties: {}
                    }
                },
                {
                    name: 'check_auth',
                    description: 'Check current GitHub authentication status',
                    inputSchema: {
                        type: 'object',
                        properties: {}
                    }
                },
                {
                    name: 'deploy',
                    description: 'Deploy code to the platform',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            folder: {
                                type: 'string',
                                description: 'Path to the folder to deploy'
                            },
                            repository: {
                                type: 'string',
                                description: 'GitHub repository URL or name (e.g., username/repo or https://github.com/username/repo)'
                            },
                            branch: {
                                type: 'string',
                                description: 'Branch to deploy'
                            }
                        },
                        required: ['folder', 'repository']
                    }
                }
            ]
        }));

        // Combined tool handler
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            switch (request.params.name) {
                case 'start_auth':
                    // Check if we already have a valid token
                    const existingToken = await this.getValidToken();
                    if (existingToken) {
                        return {
                            content: [{ type: 'text', text: 'Already authenticated with GitHub!' }]
                        };
                    }

                    // Check if there's a pending auth that hasn't expired
                    const session = await this.readSession();
                    if (session?.pendingAuth && Date.now() < session.pendingAuth.expires_at) {
                        return {
                            content: [{
                                type: 'text',
                                text: 'Authentication already in progress. Please use check_auth to check the status.'
                            }]
                        };
                    }

                    try {
                        const response = await axios.post<GitHubDeviceResponse>(
                            'https://github.com/login/device/code',
                            {
                                client_id: this.githubClientId,
                                scope: [
                                    'repo',
                                    'write:packages',
                                    'read:packages',
                                    'user:email',
                                ].join(',')
                            },
                            {
                                headers: {
                                    Accept: 'application/json'
                                }
                            }
                        );

                        const { device_code, user_code, verification_uri, expires_in, interval } = response.data;
                        await this.savePendingAuth(device_code, interval, expires_in);

                        return {
                            content: [{
                                type: 'text',
                                text: `Please visit ${verification_uri} and enter code: ${user_code}\nThis code will expire in ${expires_in} seconds.`
                            }]
                        };
                    } catch (error) {
                        console.error('Error initiating GitHub device flow:', error);
                        return {
                            content: [{ type: 'text', text: 'Failed to initiate GitHub authentication.' }],
                            isError: true
                        };
                    }

                case 'check_auth':
                    const currentSession = await this.readSession();
                    if (!currentSession?.pendingAuth) {
                        const token = await this.getValidToken();
                        return {
                            content: [{
                                type: 'text',
                                text: token
                                    ? 'Authenticated with GitHub and ready to deploy!'
                                    : 'Not authenticated. Please run start_auth to begin GitHub authentication.'
                            }]
                        };
                    }

                    // Check if pending auth has expired
                    if (Date.now() >= currentSession.pendingAuth.expires_at) {
                        await this.writeSession({ lastUsed: Date.now() }); // Clear pending auth
                        return {
                            content: [{
                                type: 'text',
                                text: 'Authentication code has expired. Please run start_auth again.'
                            }]
                        };
                    }

                    const token = await this.pollForToken(
                        currentSession.pendingAuth.device_code,
                        currentSession.pendingAuth.interval
                    );

                    if (token) {
                        await this.saveToken(token);
                        return {
                            content: [{
                                type: 'text',
                                text: 'Successfully authenticated with GitHub!'
                            }]
                        };
                    }

                    return {
                        content: [{
                            type: 'text',
                            text: `Waiting for GitHub authentication. Please enter the code in your browser.\nPolling interval: ${currentSession.pendingAuth.interval} seconds. Please try check_auth again in ${currentSession.pendingAuth.interval} seconds.`
                        }]
                    };

                case 'deploy':
                    if (!(await this.getValidToken())) {
                        return {
                            content: [{
                                type: 'text',
                                text: 'Not authenticated. Please authenticate first using start_auth.'
                            }],
                            isError: true
                        };
                    }

                    const args = request.params.arguments as DeployArguments | undefined;
                    if (!args?.folder) {
                        return {
                            content: [{
                                type: 'text',
                                text: 'Folder path is required.'
                            }],
                            isError: true
                        };
                    }

                    if (!args?.repository) {
                        return {
                            content: [{
                                type: 'text',
                                text: 'GitHub repository is required.'
                            }],
                            isError: true
                        };
                    }

                    try {
                        // Resolve the folder path to an absolute path
                        const absoluteFolderPath = path.resolve(args.folder);

                        // Verify folder exists and is writable
                        try {
                            await fs.access(absoluteFolderPath, fs.constants.W_OK | fs.constants.R_OK);
                        } catch (error) {
                            return {
                                content: [{
                                    type: 'text',
                                    text: `The path "${absoluteFolderPath}" is read-only. Please provide the complete path to your code directory where you have write permissions.`
                                }],
                                isError: true
                            };
                        }

                        // Process repository URL
                        let repoUrl: string;
                        if (args.repository.includes('github.com')) {
                            // If it's a full URL, ensure it's HTTPS
                            repoUrl = args.repository.replace('git@github.com:', 'https://github.com/');
                        } else {
                            // Validate repository name format
                            if (!/^[a-zA-Z0-9-_.]+(?:\/[a-zA-Z0-9-_.]+)?$/.test(args.repository)) {
                                return {
                                    content: [{
                                        type: 'text',
                                        text: 'Invalid repository format. Repository must be in the format "username/repository", just "repository", or a full GitHub URL.'
                                    }],
                                    isError: true
                                };
                            }
                            // If it's just username/repo or just repo, create the repository if it doesn't exist
                            try {
                                repoUrl = await this.createGitHubRepo(args.repository);
                            } catch (error) {
                                return {
                                    content: [{
                                        type: 'text',
                                        text: error instanceof Error ? error.message : 'Failed to create or access GitHub repository'
                                    }],
                                    isError: true
                                };
                            }
                        }

                        // Setup Git repository connection
                        await this.setupGitRepo(absoluteFolderPath, repoUrl);

                        // Create a new Git instance for the specified folder
                        const folderGit = simpleGit({ baseDir: absoluteFolderPath });
                        const branch = args.branch || 'main';

                        // Check repository status
                        const status = await folderGit.status();

                        // Only commit and push if there are changes
                        if (!status.isClean()) {
                            try {
                                await folderGit.add('.');
                                await folderGit.commit('Update deployment');
                            } catch (error) {
                                throw new Error('Failed to commit changes. Please commit your changes manually first.');
                            }
                        }

                        // Push changes
                        try {
                            await folderGit.push('origin', branch);
                        } catch (error) {
                            throw new Error(`Failed to push to ${branch}. Please ensure you have the correct permissions and the branch exists.`);
                        }

                        // Initiate deployment
                        const deployment = await this.deployToContainerInc(repoUrl);

                        return {
                            content: [{
                                type: 'text',
                                text: `Deployment initiated!\nTrack your deployment at: ${deployment.trackingUrl}`
                            }]
                        };
                    } catch (error) {
                        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
                        return {
                            content: [{
                                type: 'text',
                                text: `Deployment failed: ${errorMessage}`
                            }],
                            isError: true
                        };
                    }

                default:
                    return {
                        content: [{ type: 'text', text: 'Unknown tool' }],
                        isError: true
                    };
            }
        });
    }

    public async start() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
    }
}

// Start the server
const server = new DeviceFlowServer();
server.start().catch(console.error); 