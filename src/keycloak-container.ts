import { GenericContainer, StartedTestContainer, AbstractStartedContainer, Wait } from 'testcontainers'
import axios from 'axios'
import qs from 'qs'
import fs from "node:fs"
import KcAdminClient from '@keycloak/keycloak-admin-client'
import { 
  RealmRepresentation, GroupRepresentation, RoleRepresentation, UserRepresentation, 
  ClientRepresentation, CredentialRepresentation, ClientScopeRepresentation 
} from './types.js';

export class KeycloakContainer extends GenericContainer {
  private waitingLog = 'Added user \'admin\' to realm \'master\''
  private adminUsername = 'admin'
  private adminPassword = 'admin'
  private realmToImport?: string

  constructor(image: string = 'quay.io/keycloak/keycloak:24.0.1') {
    super(image)
  }

  public withWaitingLog(log: string) {
    this.waitingLog = log
    return this
  }

  public withAdminUsername(username: string): this {
    this.adminUsername = username
    return this
  }

  public withAdminPassword(password: string): this {
    this.adminPassword = password
    return this
  }

  public withImportRealm(pathToFile: string): this {
    this.realmToImport = pathToFile
    return this
  }

  public async start(): Promise<StartedKeycloakContainer> {
    this.withWaitStrategy(Wait.forLogMessage(this.waitingLog))
      .withEnvironment({ KEYCLOAK_ADMIN: this.adminUsername })
      .withEnvironment({ KEYCLOAK_ADMIN_PASSWORD: this.adminPassword })

    const command = ["start-dev"]
    if (this.realmToImport !== undefined) {
      try {
        const content = fs.readFileSync(this.realmToImport)
        this.withCopyContentToContainer([{
          content,
          target: "/opt/keycloak/data/import/realm.json"
        }])
        command.push("--import-realm")  
      } catch (e) {
        console.log("Failed to load file to import realm")
      }
    }
    this.withCommand(command)
    return new StartedKeycloakContainer(await super.start(), this.adminUsername, this.adminPassword)
  }
}

export class StartedKeycloakContainer extends AbstractStartedContainer {
  private KCADM = `/opt/keycloak/bin/kcadm.sh`
  private SERVER = 'http://localhost:8080'

  constructor(
    startedTestContainer: StartedTestContainer,
    private readonly adminUsername: string,
    private readonly adminPassword: string
  ) {
    super(startedTestContainer)
  }

  public getAdminUsername(): string {
    return this.adminUsername
  }

  public getAdminPassword(): string {
    return this.adminPassword
  }

  private async runCmd(command: string): Promise<string> {
    const commandArray = command.split(' ')
    const execResult = await this.exec(commandArray)
    if (execResult.exitCode === 0) {
      return Promise.resolve(execResult.output.trim())
    } else {
      return Promise.reject(execResult.output.trim())
    }
  }

  /**
   * Start an authenticated session on this keycloak server
   * @params realmName the realm name you want to config
   * @params user the user who starting this session, usually the username of admin
   * @params user password, usually is the password of admin
   */
  public async configCredentials(realmName: string, user: string, password: string): Promise<string> {
    return await this.runCmd(
      `${this.KCADM} config credentials --server ${this.SERVER} --realm ${realmName} --user ${user} --password ${password}`
    )
  }

  public get baseURL(): URL {
    return new URL(`http://${this.getHost()}:${this.getMappedPort(8080)}`)
  }

  public async getAdminAccessToken(): Promise<string> {
    const tokenEndpoint = new URL('realms/master/protocol/openid-connect/token', this.baseURL).toString()
    const payload = qs.stringify({
      username: this.adminUsername,
      password: this.adminPassword,
      client_id: 'admin-cli',
      grant_type: 'password',
      scope: 'openid'
    })
    try {
      const response = await axios.post(tokenEndpoint, payload, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      })

      return response.data.access_token
    } catch (error: any) {
      throw new Error(`Failed to get admin access token: ${error.message}`)
    }
  }

  public async getAuthenticatedAdminClient(): Promise<KcAdminClient> {
    const adminClient = new KcAdminClient({
      baseUrl: this.baseURL.toString(),
      realmName: 'master'
    })
    await adminClient.auth({
      username: this.adminUsername,
      password: this.adminPassword,
      grantType: 'password',
      clientId: 'admin-cli'
    })
    return adminClient
  }

  public async importRealm(realmName: string, filePath: string): Promise<string> {
    return await this.runCmd(`${this.KCADM} update realms/${realmName} -f ${filePath}`)
  }

  public async createRealm(realmName: string, enabled: boolean = true): Promise<void> {
    const adminClient = await this.getAuthenticatedAdminClient()
    const realm = {
      realm: realmName,
      enabled: enabled
    }
    try {
      await adminClient.realms.create(realm)
    } catch (error: any) {
      throw new Error(`Failed to create realm: ${error.message}`)
    }
  }

  public async getRealm(realmName: string): Promise<RealmRepresentation | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      const realm = await adminClient.realms.findOne({ realm: realmName });
      return realm;
    } catch (error: any) {
      throw new Error(`Failed to get realm: ${error.message}`);
    }
  }

  public async createGroup(realmName: string, groupName: string): Promise<string> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.groups.create({
        realm: realmName,
        name: groupName
      });
      return Promise.resolve(`Group ${groupName} created successfully in realm ${realmName}`);
    } catch (error: any) {
      throw new Error(`Failed to create group: ${error.message}`);
    }
  }

  public async getGroupIdByName(realmName: string, groupName: string): Promise<string | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      const groups = await adminClient.groups.find({
        realm: realmName,
        search: groupName
      });

      return groups.find(g => g.name === groupName)?.id;
    } catch (error: any) {
      throw new Error(`Failed to get group: ${error.message}`);
    }
  }
  
  public async createRealmRole(realmName: string, role: string, description: string = ""): Promise<void> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.roles.create({
        realm: realmName,
        name: role,
        description: description
      });
    } catch (error: any) {
      throw new Error(`Failed to create realm role: ${error.message}`);
    }
  }

  public async createClientRole(realmName: string, clientUniqueId: string, role: string, description: string = ""): Promise<void> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.clients.createRole({
        id: clientUniqueId,
        realm: realmName,
        name: role,
        clientRole: true,
        description: description
      });
    } catch (error: any) {
      throw new Error(`Failed to create client role: ${error.message}`);
    }
  }

  public async getRealmRoleByName(realmName: string, roleName: string): Promise<RoleRepresentation | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.roles.findOneByName({
        realm: realmName,
        name: roleName
      });
    } catch (error: any) {
      throw new Error(`Failed to get realm role: ${error.message}`);
    }
  }

  public async getClientRoleByName(realmName: string, clientUniqueId: string, roleName: string): Promise<RoleRepresentation | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.clients.findRole({
        realm: realmName,
        id: clientUniqueId,
        roleName: roleName
      });
    } catch (error: any) {
      throw new Error(`Failed to get client role: ${error.message}`);
    }
  }

  public async getRoleById(realmName: string, roleId: string): Promise<RoleRepresentation | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.roles.findOneById({
        realm: realmName,
        id: roleId
      });
    } catch (error: any) {
      throw new Error(`Failed to get realm role: ${error.message}`);
    }
  }

  public async createUser(realmName: string, user: UserRepresentation): Promise<void> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.users.create({
        ...user,
        realm: realmName,
      });
    } catch (error: any) {
      throw new Error(`Failed to create user: ${error.message}`);
    }
  }
  
  public async getUserById(realmName: string, userId: string): Promise<UserRepresentation | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.users.findOne({
        realm: realmName,
        id: userId
      });
    } catch (error: any) {
      throw new Error(`Failed to get user: ${error.message}`);
    }
  }

  public async getUserIdByUsername(realmName: string, username: string): Promise<string | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      const users = await adminClient.users.find({
        realm: realmName,
        username: username
      });
      return users.find(user => user.username === username)?.id;
    } catch (error: any) {
      throw new Error(`Failed to get user ID: ${error.message}`);
    }
  }

  public async setUserPassword(realmName: string, username: string, password: string): Promise<void> {
    const userId = await this.getUserIdByUsername(realmName, username);
    if (userId === undefined) {
      throw new Error(`Cannot find user ${username} in realm ${realmName}`);
    }
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.users.resetPassword({
        realm: realmName,
        id: userId,
        credential: {
          temporary: false,
          type: 'password',
          value: password
        }
      });
    } catch (error: any) {
      throw new Error(`Failed to set user password: ${error.message}`);
    }
  }

  public async addUserToGroup(realmName: string, username: string, group: string): Promise<void> {
    const adminClient = await this.getAuthenticatedAdminClient();
    const userId = await this.getUserIdByUsername(realmName, username);
    if (userId === undefined) {
      throw new Error(`Cannot find user ${username} in realm ${realmName}`);
    }
    const groupId = await this.getGroupIdByName(realmName, group);
    if (groupId === undefined) {
      throw new Error(`Cannot find group ${group} in realm ${realmName}`);
    }
    try {
      await adminClient.users.addToGroup({
        realm: realmName,
        id: userId,
        groupId: groupId
      });
    } catch (error: any) {
      throw new Error(`Failed to add user to group: ${error.message}`);
    }
  }

  public async getGroupsFromUser(realmName: string, username: string): Promise<Array<GroupRepresentation>> {
    const adminClient = await this.getAuthenticatedAdminClient();
    const userId = await this.getUserIdByUsername(realmName, username);
    if (userId === undefined) {
      throw new Error(`Cannot find user ${username} in realm ${realmName}`);
    }
    try {
      return await adminClient.users.listGroups({
        realm: realmName,
        id: userId,
        briefRepresentation: true
      });
    } catch (error: any) {
      throw new Error(`Failed to get groups from user: ${error.message}`);
    }
  }

  public async getAssignedRealmRolesFromUser(realmName: string, username: string): Promise<Array<RoleRepresentation>> {
    const adminClient = await this.getAuthenticatedAdminClient();
    const userId = await this.getUserIdByUsername(realmName, username);
    if (userId === undefined) {
      throw new Error(`Cannot find user ${username} in realm ${realmName}`);
    }
    try {
      return adminClient.users.listRealmRoleMappings({
        realm: realmName,
        id: userId
      })  
    } catch (error: any) {
      throw new Error(`Failed to get assigned realm roles from user: ${error.message}`);
    }
  }

  public async getAssignedClientRolesFromUser(realmName: string, username: string, clientUniqueId: string): Promise<Array<RoleRepresentation>> {
    const adminClient = await this.getAuthenticatedAdminClient();
    const userId = await this.getUserIdByUsername(realmName, username);
    if (userId === undefined) {
      throw new Error(`Cannot find user ${username} in realm ${realmName}`);
    }
    try {
      return adminClient.users.listClientRoleMappings({
        realm: realmName,
        id: userId,
        clientUniqueId
      })  
    } catch (error: any) {
      throw new Error(`Failed to get assigned client roles from user: ${error.message}`);
    }
  }

  public async assignRealmRoleToUser(realmName: string, username: string, roleName: string) {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      const userId = await this.getUserIdByUsername(realmName, username);
      if (userId === undefined) {
        throw new Error(`Cannot find user ${username} in realm ${realmName}`);
      }
      const role = await this.getRealmRoleByName(realmName, roleName);
      if (role === undefined) {
        throw new Error(`Cannot find realm role ${roleName} in realm ${realmName}`);
      }
      await adminClient.users.addRealmRoleMappings({
        realm: realmName,
        id: userId,
        roles: [{
          id: role.id as string,
          name: role.name as string
        }]
      });
    } catch (error: any) {
      throw new Error(`Failed to assign realm role to user: ${error.message}`);
    }
  }

  public async assignClientRoleToUser(realmName: string, username: string, clientUniqueId: string, roleName: string) {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      const userId = await this.getUserIdByUsername(realmName, username);
      if (userId === undefined) {
        throw new Error(`Cannot find user ${username} in realm ${realmName}`);
      }
      const role = await this.getClientRoleByName(realmName, clientUniqueId, roleName);
      if (role === undefined) {
        throw new Error(`Cannot find client role ${roleName} in realm ${realmName}`);
      }
      await adminClient.users.addClientRoleMappings({
        realm: realmName,
        id: userId,
        clientUniqueId,
        roles: [{
          id: role.id as string,
          name: role.name as string
        }]
      });
    } catch (error: any) {
      throw new Error(`Failed to assign client role to user: ${error.message}`);
    }
  }

  public async createClient(realmName: string, client: ClientRepresentation): Promise<void> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.clients.create({
        ...client,
        realm: realmName,
      });
    } catch (error: any) {
      throw new Error(`Failed to create client: ${error.message}`);
    }
  }

  public async getCidByClientId(realmName: string, clientId: string): Promise<string | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    const clients: Array<ClientRepresentation> = await adminClient.clients.find({
      realm: realmName,
      clientId: clientId
    });
    return clients?.[0]?.id
  }

  public async getClientByCid(realmName: string, cid: string): Promise<ClientRepresentation | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.clients.findOne({
        id: cid,
        realm: realmName
      });
    } catch (error: any) {
      throw new Error(`Failed to get client: ${error.message}`);
    }
  }

  public async getClientSecretByCid(realmName: string, cid: string): Promise<CredentialRepresentation> {
    const adminClient = await this.getAuthenticatedAdminClient();
    return await adminClient.clients.getClientSecret({
      id: cid,
      realm: realmName
    })
  }

  public async createClientScope(realmName: string, clientScope: ClientScopeRepresentation): Promise<void> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.clientScopes.create({
        ...clientScope,
        realm: realmName
      });
    } catch (error: any) {
      throw new Error(`Failed to create client scope: ${error.message}`);
    }
  }

  public async getClientScopeIdByName(realmName: string, clientScopeName: string): Promise<string | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      const clientScopes = await adminClient.clientScopes.find({
        realm: realmName,
      });
      const clientScope = clientScopes.find(cs => cs.name === clientScopeName);
      return clientScope?.id;
    } catch (error: any) {
      throw new Error(`Failed to get client scope: ${error.message}`);
    }
  }

  public async getClientScopeById(realmName: string, clientScopeId: string): Promise<ClientScopeRepresentation | undefined> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.clientScopes.findOne({
        id: clientScopeId,
        realm: realmName
      });
    } catch (error: any) {
      throw new Error(`Failed to get client scope: ${error.message}`);
    }
  }

  public async addDefaultClientScopeToClient(realmName: string, cid: string, clientScopeId: string) {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.clients.addDefaultClientScope({
        id: cid,
        realm: realmName,
        clientScopeId: clientScopeId
      });
    } catch (error: any) {
      throw new Error(`Failed to add client scope to client: ${error.message}`);
    }
  }

  public async addOptionalClientScopeToClient(realmName: string, cid: string, clientScopeId: string) {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      await adminClient.clients.addOptionalClientScope({
        id: cid,
        realm: realmName,
        clientScopeId: clientScopeId
      });
    } catch (error: any) {
      throw new Error(`Failed to add client scope to client: ${error.message}`);
    }
  }

  public async getDefaultClientScopesFromClient(realmName: string, cid: string, optional: boolean): Promise<Array<ClientScopeRepresentation>> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.clients.listDefaultClientScopes({
        id: cid,
        realm: realmName,
      });
    } catch (error: any) {
      throw new Error(`Failed to get client scopes from client: ${error.message}`);
    }
  }

  public async getOptionalClientScopesFromClient(realmName: string, cid: string): Promise<Array<ClientScopeRepresentation>> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.clients.listOptionalClientScopes({
        id: cid,
        realm: realmName,
      });
    } catch (error: any) {
      throw new Error(`Failed to get client scopes from client: ${error.message}`);
    }
  }

  public async getServiceAccountUserFromClient(realmName: string, cid: string): Promise<UserRepresentation> {
    const adminClient = await this.getAuthenticatedAdminClient();
    try {
      return await adminClient.clients.getServiceAccountUser({
        id: cid,
        realm: realmName
      });
    } catch (error: any) {
      throw new Error(`Failed to get service account user from client: ${error.message}`);
    }
  }

  public async getAccessToken(
    realmName: string,
    username: string,
    password: string,
    clientId: string,
    clientSecret: string,
  ): Promise<string> {
    const tokenEndpoint = new URL(`realms/${realmName}/protocol/openid-connect/token`, this.baseURL).toString()

    const payload = qs.stringify({
      username,
      password,
      grant_type: 'password'
    })

    try {
      const response = await axios.post(tokenEndpoint, payload, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        auth: {
          username: clientId,
          password: clientSecret
        }
      })
      const accessToken: string = response.data['access_token']
      if (accessToken) {
        return accessToken
      } else {
        throw new Error(`Failed to get access_token: access_token undefined`)
      }
    } catch (error) {
      throw new Error(`Failed to get access_token: ${error}`)
    }
  }

  public async getIdToken(
    realmName: string,
    username: string,
    password: string,
    clientId: string,
    clientSecret: string
  ): Promise<string> {
    const tokenEndpoint = new URL(`realms/${realmName}/protocol/openid-connect/token`, this.baseURL).toString()

    const payload = qs.stringify({
      username,
      password,
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'password',
      scope: 'openid'
    })

    try {
      const response = await axios.post(tokenEndpoint, payload)
      const idToken: string = response.data['id_token']
      if (idToken) {
        return idToken
      } else {
        throw new Error(`Failed to get id_token: id_token undefined`)
      }
    } catch (error) {
      throw new Error(`Failed to get id_token: ${error}`)
    }
  }
}
