const { performance } = require('perf_hooks')
const { fetch } = require('undici')
const Parser = require('./parser')
const Parser2 = require('./parser_v2')
const ServerAPI = require('./api.js')

async function parseAndCreateCommit({
  data,
  streamId,
  branchName = 'uploads',
  userId,
  message = 'Manual IFC file upload'
}) {
  const serverApi = new ServerAPI({ streamId })
  const myParser = new Parser({ serverApi })
  const myParser2 = new Parser2({ serverApi })

  const start2 = performance.now()
  const { id, tCount } = await myParser2.parse(data)
  const end2 = performance.now()

  // const start = performance.now()
  // const { id, tCount } = await myParser.parse(data)
  // const end = performance.now()

  //   console.log(`

  // Total processing time V1: ${(end - start).toFixed(2)}ms
  // Total processing time V2: ${(end2 - start2).toFixed(2)}ms

  //   `)
  console.log(`

Total processing time V2: ${(end2 - start2).toFixed(2)}ms

  `)

  const commit = {
    streamId,
    branchName,
    objectId: id,
    message,
    sourceApplication: 'IFC',
    totalChildrenCount: tCount
  }

  const branch = await serverApi.getBranchByNameAndStreamId({
    streamId,
    name: branchName
  })

  if (!branch) {
    await serverApi.createBranch({
      name: branchName,
      streamId,
      description: branchName === 'uploads' ? 'File upload branch' : null,
      authorId: userId
    })
  }

  const userToken =
    process.env.USER_TOKEN || 'cb1d6e2e2d97450738eb0f6b07c596acad625a720c'

  const serverBaseUrl = process.env.SPECKLE_SERVER_URL || 'http://localhost:3000'
  const response = await fetch(serverBaseUrl + '/graphql', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${userToken}`
    },
    body: JSON.stringify({
      query:
        'mutation createCommit( $myCommitInput: CommitCreateInput!) { commitCreate( commit: $myCommitInput ) }',
      variables: {
        myCommitInput: commit
      }
    })
  })

  const json = await response.json()
  // eslint-disable-next-line no-console
  console.log(json)

  return json.data.commitCreate
}

module.exports = { parseAndCreateCommit }
