import { GenericContainer, StartedTestContainer, AbstractStartedContainer, Wait } from 'testcontainers'
import { ClientSecret, KeycloakClient, KeycloakGroup, KeycloakRealm, KeycloakRole, KeycloakUser } from './types.js'
import axios from 'axios'
import qs from 'qs'
import fs from "node:fs"

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
   * @params realmName th3 realm name you want to config
   * @params user the user who starting this session, usually the username of admin
   * @params user password, usually is the password of admin
   */
  public async configCredentials(realmName: string, user: string, password: string): Promise<string> {
    return await this.runCmd(
      `${this.KCADM} config credentials --server ${this.SERVER} --realm ${realmName} --user ${user} --password ${password}`
    )
  }

  public async importRealm(realmName: string, filePath: string): Promise<string> {
    return await this.runCmd(`${this.KCADM} update realms/${realmName} -f ${filePath}`)
  }

  public async createRealm(realmName: string, enabled: boolean = true): Promise<string> {
    return await this.runCmd(`${this.KCADM} create realms -s realm=${realmName} -s enabled=${enabled}`)
  }

  public async getRealm(realmName: string): Promise<KeycloakRealm> {
    const realmResult = await this.runCmd(`${this.KCADM} get realms/${realmName}`)
    const realm: KeycloakRealm = JSON.parse(realmResult)
    return realm
  }

  public async createGroup(
    realmName: string,
    groupName: string
  ): Promise<string> {
    return await this.runCmd(
      `${this.KCADM} create groups -r ${realmName} -s name=${groupName}`
    )
  }

  public async getGroupIdByName(
    realmName: string,
    groupName: string
  ): Promise<string> {
    const groupsResult = await this.runCmd(
      `${this.KCADM} get groups -r ${realmName} --fields id,name`
    )
    const groups: Array<KeycloakGroup> = JSON.parse(groupsResult)
    const group = groups.find(g => g.name === groupName)
    if (group !== undefined) {
      return Promise.resolve(group.id)
    } else {
      return Promise.reject(`Cannot find group with name ${groupName} in realm ${realmName}`)
    }
  }

  public async createRealmRole(
    realmName: string,
    role: string,
    description: string = ""
  ): Promise<string> {
    return await this.runCmd(
      `${this.KCADM} create roles -r ${realmName} -s name=${role} -s description=${description}`
    )
  }

  public async getRealmRoleIdByName(
    realmName: string,
    roleName: string
  ): Promise<string> {
    const rolesResult = await this.runCmd(
      `${this.KCADM} get roles -r ${realmName} --fields id,name`
    )
    const roles: Array<KeycloakRole> = JSON.parse(rolesResult)
    const role = roles.find(g => g.name === roleName)
    if (role !== undefined) {
      return Promise.resolve(role.id)
    } else {
      return Promise.reject(`Cannot find role with name ${roleName} in realm ${realmName}`)
    }
  }

  public async createUser(
    realmName: string,
    username: string,
    email: string,
    firstName: string,
    lastName: string,
    emailVerified: boolean = true,
    enabled: boolean = true
  ): Promise<string> {
    return await this.runCmd(
      `${this.KCADM} create users -r ${realmName} -s username=${username} -s email=${email} -s emailVerified=${emailVerified} -s firstName=${firstName} -s lastName=${lastName} -s enabled=${enabled}`
    )
  }

  public async getUserById(realmName: string, userId: string): Promise<KeycloakUser> {
    const userResult = await this.runCmd(`${this.KCADM} get users/${userId} -r ${realmName}`)
    const user: KeycloakUser = JSON.parse(userResult)
    return user
  }

  public async getUserIdByUsername(realmName: string, username: string): Promise<string> {
    const usersResult = await this.runCmd(`${this.KCADM} get users -r ${realmName} -q username=${username}`)
    const userArray: Array<KeycloakUser> = JSON.parse(usersResult)
    let userId: string | undefined
    
    // The -q username=<value> match is not exact so we may end with multiple entries
    if (userArray.length > 0) {
      userId = userArray.find(user => user.username === username)?.id
    }
    
    if (userId !== undefined) {
      return Promise.resolve(userId)
    } else {
      return Promise.reject(`Cannot find username '${username}' in realm '${realmName}'`)
    }
  }

  public async setUserPassword(realmName: string, username: string, password: string): Promise<string> {
    return await this.runCmd(
      `${this.KCADM} set-password -r ${realmName} --username ${username} --new-password ${password}`
    )
  }

  public async addUserToGroup(realmName: string, username: string, group: string): Promise<string> {
    const userId: string = await this.getUserIdByUsername(realmName, username)
    const groupId: string = await this.getGroupIdByName(realmName, group)
    try {
      return await this.runCmd(
        `${this.KCADM} update users/${userId}/groups/${groupId} -r ${realmName} -s userId=${userId} -s groupId=${groupId} -n`
      )
    } catch (e) {
      return Promise.reject(`Failed to add user ${username} of realm ${realmName} to group ${group}`)
    }
  }

  public async getGroupsFromUser(realmName: string, username: string): Promise<Array<KeycloakGroup>> {
    const userId: string = await this.getUserIdByUsername(realmName, username)
    const cmdResult = await this.runCmd(`${this.KCADM} get users/${userId}/groups -r ${realmName}`)
    return JSON.parse(cmdResult)
  }

  public async getAssignedRealmRolesFromUser(realmName: string, username: string): Promise<Array<KeycloakRole>> {
    const cmdResult = await this.runCmd(`${this.KCADM} get-roles -r ${realmName} --uusername ${username}`)
    return JSON.parse(cmdResult)
  }

  public async assignRealmRoleToUser(realmName: string, username: string, role: string): Promise<string> {
    return await this.runCmd(`${this.KCADM} add-roles -r ${realmName} --uusername ${username} --rolename ${role}`)
  }

  public async createClient(
    realmName: string,
    clientId: string,
    clientSecret: string,
    redirectUris: Array<string> = [],
    webOrigins: Array<string> = [],
    directAccessGrantsEnabled: boolean = true,
    enabled: boolean = true
  ): Promise<string> {
    const redirectUrisString = redirectUris.map((uri) => `"${uri}"`).join(',')
    const webOriginsString = webOrigins.map((uri) => `"${uri}"`).join(',')
    return await this.runCmd(
      `${this.KCADM} create clients -r ${realmName} -s clientId=${clientId} -s secret=${clientSecret} -s enabled=${enabled} -s redirectUris=[${redirectUrisString}] -s webOrigins=[${webOriginsString}] -s directAccessGrantsEnabled=${directAccessGrantsEnabled}`
    )
  }

  public async getCidByClientId(realmName: string, clientId: string): Promise<string> {
    const clientsResult = await this.runCmd(
      `${this.KCADM} get clients -r ${realmName} --fields id -q clientId=${clientId}`
    )
    const clients: Array<KeycloakClient> = JSON.parse(clientsResult)
    if (clients.length === 1) {
      return Promise.resolve(clients[0]['id'])
    } else {
      return Promise.reject(`Can't find client '${clientId}' in realm '${realmName}'`)
    }
  }

  public async getClientByCid(realmName: string, cid: string): Promise<KeycloakClient> {
    const clientResult = await this.runCmd(`${this.KCADM} get clients/${cid} -r ${realmName}`)
    const client: KeycloakClient = JSON.parse(clientResult)
    return client
  }

  public async getClientSecretByCid(realmName: string, cid: string): Promise<ClientSecret> {
    const clientSecretResult = await this.runCmd(`${this.KCADM} get clients/${cid}/client-secret -r ${realmName}`)
    const secret: ClientSecret = JSON.parse(clientSecretResult)
    return secret
  }

  public async getAccessToken(
    realmName: string,
    username: string,
    password: string,
    clientId: string,
    clientSecret: string,
  ): Promise<string> {
    const tokenEndpoint = `http://${this.getHost()}:${this.getMappedPort(
      8080
    )}/realms/${realmName}/protocol/openid-connect/token`

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
    const tokenEndpoint = `http://${this.getHost()}:${this.getMappedPort(
      8080
    )}/realms/${realmName}/protocol/openid-connect/token`

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
