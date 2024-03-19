import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { KeycloakContainer, StartedKeycloakContainer } from '../src/keycloak-container'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import fs from "node:fs/promises"

describe('Keycloak Container Test', () => {
  let keycloak: StartedKeycloakContainer

  beforeAll(async () => {
    const mypath = path.dirname(fileURLToPath(import.meta.url));
    const realmToImport = path.join(mypath, 'resources/realm-export.json')
    keycloak = await new KeycloakContainer()
      .withStartupTimeout(600_000)
      .withAdminUsername('admin')
      .withAdminPassword('admin')
      .withImportRealm(realmToImport)
      .withExposedPorts(8080)
      .start()
    await keycloak.configCredentials('master', 'admin', 'admin')
  })

  afterAll(async () => {
    await keycloak.stop()
  });

  it('should return whoami result', async () => {
    const whoamiResult = 
    await keycloak.exec(['whoami'])

    expect(whoamiResult.exitCode).toBe(0)
    expect(whoamiResult.output.trim()).toBe('keycloak')
  })

  it('should have imported the realm', async () => {
    const realm = await keycloak.getRealm('main')
    const sensorRoleId = await keycloak.getRealmRoleIdByName('main', 'sensor')
    
    expect(realm.realm).toBe('main')
    expect(sensorRoleId).toBeDefined()
  })

  it('realm operations: create, get', async () => {
    await keycloak.createRealm('demo')
    const realmResult = await keycloak.getRealm('demo')

    expect(realmResult.realm).toBe('demo')
  })

  it('user operations: create, get, set-password', async () => {
    await keycloak.createUser('demo', 'user01', 'user01@example.com', 'yubin', 'hsu', true, true)
    const userId = await keycloak.getUserIdByUsername('demo', 'user01')
    const user = await keycloak.getUserById('demo', userId)
    await keycloak.setUserPassword('demo', 'user01', 'user01password')

    expect(userId).toBeDefined()
    expect(user.id).toBe(userId)
    expect(user.username).toBe('user01')
  })

  it('create and retrieve group: create, get', async () => {
    await keycloak.createGroup('demo', 'group1')
    const groupId = await keycloak.getGroupIdByName('demo', 'group1')

    expect(groupId).toBeDefined()
  })

  it('add a user to a group', async () => {
    await keycloak.createUser('demo', 'user02', 'user02@example.com', 'User', 'Zerotwo', true, true)
    await keycloak.createGroup('demo', 'group2')
    await keycloak.addUserToGroup('demo', 'user02', 'group2')
    const groups = await keycloak.getGroupsFromUser('demo', 'user02')
    expect(groups.map(g => g.name)).includes('group2')
  })

  it('create and retrieve role', async () => {
    await keycloak.createRealmRole('demo', 'role1')
    const roleId = await keycloak.getRealmRoleIdByName('demo', 'role1')

    expect(roleId).toBeDefined()
  })

  it('assign role to a user', async () => {
    await keycloak.assignRealmRoleToUser('demo', 'user02', 'role1')
    const roles = await keycloak.getAssignedRealmRolesFromUser('demo', 'user02')

    expect(roles.map(r => r.name)).include('role1')
  })

  it('client operations: create, get', async () => {
    await keycloak.createClient(
      'demo',
      'client01',
      'client01Secret',
      ['http://localhost:8888', 'http://localhost:8888/callback'],
      ['http://localhost:8888/home']
    )
    const cid = await keycloak.getCidByClientId('demo', 'client01')
    const client = await keycloak.getClientByCid('demo', cid)
    const clientSecret = await keycloak.getClientSecretByCid('demo', cid)

    expect(client.id).toBe(cid)
    expect(client.clientId).toBe('client01')
    expect(client.redirectUris).toHaveLength(2)
    expect(client.webOrigins).toHaveLength(1)
    expect(clientSecret.value).toBe('client01Secret')
  })

  it.fails('when get cid with a non-exist client', async () => {
     await keycloak.getCidByClientId('demo','non-exist-client-id')
  })

  it('should get access_token', async () => {
    const accessToken = await keycloak.getAccessToken('demo', 'user01@example.com', 'user01password', 'client01', 'client01Secret')
    expect(accessToken).toBeTruthy()
  })

  it('should not get access_token when given a fake user', async () => {
    await expect(
      keycloak.getAccessToken('demo', 'fakeUser@example.com', 'user01password', 'client01', 'client01Secret')
    ).rejects.toThrow()
  })

  it('should get id_token', async () => {
    const idToken = await keycloak.getIdToken('demo', 'user01', 'user01password', 'client01', 'client01Secret')
    expect(idToken).toBeTruthy()
  })

  it('should not get id_token when given a fake user', async () => {
    await expect(
      keycloak.getIdToken('demo', 'fakeUser', 'user01password', 'client01', 'client01Secret')
    ).rejects.toThrow()
  })

  it('should return admin username', () => {
    const username = keycloak.getAdminUsername()
    expect(username).toBe('admin')
  })

  it('should return admin password', () => {
    const password = keycloak.getAdminPassword()
    expect(password).toBe('admin')
  })

  it.fails('when get a non-exist user', async () => {
    await keycloak.getUserIdByUsername('demo', 'non-exist-user')
  })

})