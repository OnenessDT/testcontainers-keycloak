import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { KeycloakContainer, StartedKeycloakContainer } from '../src/keycloak-container'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import UserRepresentation from '@keycloak/keycloak-admin-client/lib/defs/userRepresentation'
import ClientRepresentation from '@keycloak/keycloak-admin-client/lib/defs/clientRepresentation'
import ClientScopeRepresentation from '@keycloak/keycloak-admin-client/lib/defs/clientScopeRepresentation'

describe('Keycloak Container Test', () => {
  let keycloak: StartedKeycloakContainer

  beforeAll(async () => {
    const mypath = path.dirname(fileURLToPath(import.meta.url))
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
  })

  it('should return whoami result', async () => {
    const whoamiResult = 
    await keycloak.exec(['whoami'])

    expect(whoamiResult.exitCode).toBe(0)
    expect(whoamiResult.output.trim()).toBe('keycloak')
  })

  it('should have imported the realm', async () => {
    const realm = await keycloak.getRealm('main')
    const sensorRoleId = await keycloak.getRealmRoleByName('main', 'sensor')
    
    expect(realm).to.be.an('object').that.have.property('realm')
    expect(realm).to.have.property('realm', 'main')
    expect(sensorRoleId).to.have.property('name', 'sensor')
  })

  it('should create and get realms', async () => {
    await keycloak.createRealm('demo')
    const realmResult = await keycloak.getRealm('demo')

    expect(realmResult).to.be.an('object').that.have.property('realm')
    expect(realmResult?.realm).toBe('demo')
  })

  it('should create and get users and set their password', async () => {
    const userRepr: UserRepresentation = {
      username: 'user01',
      email: 'user01@example.com',
      firstName: 'User',
      lastName: 'Zero-One',
      enabled: true,
      emailVerified: true
    }
    await keycloak.createUser('demo', userRepr)
    const userId = await keycloak.getUserIdByUsername('demo', 'user01')
    expect(userId).to.be.a('string')
    const user = await keycloak.getUserById('demo', userId as string)
    await keycloak.setUserPassword('demo', 'user01', 'user01password')
    expect(user).to.have.property('id', userId)
    expect(user).to.have.property('username', 'user01')
  })

  it('should create and retrieve groups', async () => {
    await keycloak.createGroup('demo', 'group1')
    const groupId = await keycloak.getGroupIdByName('demo', 'group1')

    expect(groupId).to.be.a('string')
  })

  it('should add a user to a group', async () => {
    await keycloak.createUser('demo', {
      username: 'user02', 
      email: 'user02@example.com', 
      firstName: 'User', 
      lastName: 'Zerotwo', 
      emailVerified: true, 
      enabled: true
    })
    await keycloak.createGroup('demo', 'group2')
    await keycloak.addUserToGroup('demo', 'user02', 'group2')
    const groups = await keycloak.getGroupsFromUser('demo', 'user02')
    expect(groups.map(g => g.name)).includes('group2')
  })

  it('should create and retrieve clients', async () => {
    const clientRepr: ClientRepresentation = {
      clientId: 'client01',
      secret: 'client01Secret',
      redirectUris: ['http://localhost:8888', 'http://localhost:8888/callback'],
      webOrigins: ['http://localhost:8888/home'],
      directAccessGrantsEnabled: true,
    }
    await keycloak.createClient(
      'demo',
      clientRepr
    )
    const cid = await keycloak.getCidByClientId('demo', 'client01')

    expect(cid).to.be.a('string')

    const client = await keycloak.getClientByCid('demo', cid as string)
    const clientSecret = await keycloak.getClientSecretByCid('demo', cid as string)

    expect(client).to.have.property('id', cid)
    expect(client).to.have.property('clientId', 'client01')
    expect(client).to.have.property('redirectUris').that.have.lengthOf(2)
    expect(client).to.have.property('webOrigins').that.have.lengthOf(1)
    expect(clientSecret).to.have.property('value', 'client01Secret')
  })

  it('should return undefined for a non-existent client', async () => {
     const clientId = await keycloak.getCidByClientId('demo','non-exist-client-id')
     expect(clientId).to.be.undefined
  })

  it('should create a client scope', async () => {
    const scope: ClientScopeRepresentation = {
      name: 'scope1',
      description: 'scope1',
      protocol: 'openid-connect',
      attributes: {},
    }
    await keycloak.createClientScope('demo', scope)
    const scopeId = await keycloak.getClientScopeIdByName('demo', 'scope1')
    expect(scopeId).to.be.a('string')
    const storedScope = await keycloak.getClientScopeById('demo', scopeId as string)
    expect(storedScope).to.have.property('name', 'scope1')
  })

  it('should create a client scope and add it as default scope to a client', async () => {
    const scope: ClientScopeRepresentation = {
      name: 'scope2',
      description: 'scope2',
      protocol: 'openid-connect',
      attributes: {},
    }
    await keycloak.createClientScope('demo', scope)
    const scopeId = await keycloak.getClientScopeIdByName('demo', 'scope2')
    expect(scopeId).to.be.a('string')
    const cid = await keycloak.getCidByClientId('demo', 'client01')
    expect(cid).to.be.a('string')
    await keycloak.addDefaultClientScopeToClient('demo', cid as string, scopeId as string)
    const client = await keycloak.getClientByCid('demo', cid as string)
    expect(client).to.have.property('defaultClientScopes').that.contains('scope2')
  })

  it('should create a client scope and add it as optional scope to a client', async () => {
    const scope: ClientScopeRepresentation = {
      name: 'scope3',
      description: 'scope3',
      protocol: 'openid-connect',
      attributes: {},
    }
    await keycloak.createClientScope('demo', scope)
    const scopeId = await keycloak.getClientScopeIdByName('demo', 'scope3')
    expect(scopeId).to.be.a('string')
    const cid = await keycloak.getCidByClientId('demo', 'client01')
    expect(cid).to.be.a('string')
    await keycloak.addOptionalClientScopeToClient('demo', cid as string, scopeId as string)
    const client = await keycloak.getClientByCid('demo', cid as string)
    expect(client).to.have.property('optionalClientScopes').that.contains('scope3')
  })

  it('should create and retrieve realm role', async () => {
    await keycloak.createRealmRole('demo', 'role1')
    const role = await keycloak.getRealmRoleByName('demo', 'role1')

    expect(role).to.have.property('name', 'role1')
  })

  it('should create and retrieve client role', async () => {
    const cid = await keycloak.getCidByClientId('demo', 'client01') as string
    await keycloak.createClientRole('demo', cid, 'role2')
    const role = await keycloak.getClientRoleByName('demo', cid, 'role2')

    expect(role).to.have.property('name', 'role2')
  })

  it('should assign realm role to a user', async () => {
    await keycloak.assignRealmRoleToUser('demo', 'user02', 'role1')
    const roles = await keycloak.getAssignedRealmRolesFromUser('demo', 'user02')

    expect(roles.map(r => r.name)).include('role1')
  })

  it('should assign client role to a user', async () => {
    const cid = await keycloak.getCidByClientId('demo', 'client01') as string
    await keycloak.assignClientRoleToUser('demo', 'user02', cid, 'role2')
    const roles = await keycloak.getAssignedClientRolesFromUser('demo', 'user02', cid)

    expect(roles.map(r => r.name)).include('role2')
  })

  it('should retrieve service account user for client with service account enabled', async () => {
    await keycloak.createClient('demo', {
      clientId: 'clientWithServiceAccount',
      serviceAccountsEnabled: true
    })
    const cid = await keycloak.getCidByClientId('demo', 'clientWithServiceAccount') as string
    const user = await keycloak.getServiceAccountUserFromClient('demo', cid)

    expect(user).to.have.property('username', 'service-account-clientwithserviceaccount')
  })

  it('should throw exception when retrieving service account user for client with service account disabled', async () => {
    await keycloak.createClient('demo', {
      clientId: 'clientWithoutServiceAccount',
      serviceAccountsEnabled: false
    })
    const cid = await keycloak.getCidByClientId('demo', 'clientWithoutServiceAccount') as string
    await expect(keycloak.getServiceAccountUserFromClient('demo', cid)).rejects.toThrow()
  })

  it('should get access_token for client with service accounts enabled', async () => {
    await keycloak.createClient('demo', {
      clientId: 'clientToTestGetAccessTokenForClient',
      secret: 'clientpassword',
      serviceAccountsEnabled: true,
    })
    const accessToken = await keycloak.getAccessTokenForClient('demo', 'clientToTestGetAccessTokenForClient', 'clientpassword')
    expect(accessToken).to.be.a('string').that.is.not.empty
  })

  it('should throw exception when getting access_token for client with service accounts disabled', async () => {
    await keycloak.createClient('demo', {
      clientId: 'clientToTestGetAccessTokenForClientWithoutServiceAccount',
      secret: 'clientpassword',
      serviceAccountsEnabled: false
    })
    await expect(keycloak.getAccessTokenForClient('demo', 'clientToTestGetAccessTokenForClientWithoutServiceAccount', 'clientpassword')).rejects.toThrow()
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

  it('should return undefined when getting a non-exist user', async () => {
    const userId = await keycloak.getUserIdByUsername('demo', 'non-exist-user')
    expect(userId).to.be.undefined
  })

})