const webapi = require('webapi-parser').WebApiParser
const raml = webapi.raml10
const oas = webapi.oas20
const fs = require('fs')
const in_path = '/dev/stdin'
const out_path = 'gen_nethsm_api_oas20.json'
const out_path_resolved = 'gen_nethsm_api_oas20_resolved.json'

// Fixes https://git.nitrokey.com/nitrokey/nethsm/nethsm/-/issues/184
// JSON API scheme does not contain produces attribute for endpoints
function fixup_produces(oasjson) {
  let oas = JSON.parse(oasjson);

  // Iterate on endpoints
  Object.keys(oas.paths).map((path) => {
    let endpoint = oas.paths[path]

    for (let meth of ["get", "post"]) {
      let responses = endpoint[meth]?.responses["200"]

      if (responses != undefined && responses["x-amf-mediaType"]) {
        let mediatypes = [ responses["x-amf-mediaType"] ]
  
        if (responses["x-amf-responsePayloads"]) {
          responses["x-amf-responsePayloads"].map(({mediaType}) => mediatypes.push(mediaType))
        }
  
        if (mediatypes.length == 1 && mediatypes[0] == 'application/json') {
          // OK: this is the default media type
        } else {
          // add a produces field
          endpoint[meth]["produces"] = mediatypes
        }
      }
    }
  })

  return JSON.stringify(oas, null, 2);
}

async function main () {
  let failed = false
  try {
    // read RAML
    ramlFile = fs.readFileSync(in_path, 'utf8')

    // parse RAML
    model = await raml.parse(ramlFile)

    // validate RAML parser model
    report = await raml.validate(model)
    console.log('RAML validation report:\n', report.toString())
    if (!report.conforms) {
      failed = true
    }

    // parse RAML again
    model = await raml.parse(ramlFile)

    // convert to OAS
    oasjson = await oas.generateString(model)

    // patch some issues
    oasjson = oasjson.replace(/{host}/g, "nethsmdemo.nitrokey.com",)
    oasjson = oasjson.replace(/{version}/g, "v1")
    oasjson = oasjson.replace(/"name": "generated"/g, '"name": "body"')
    oasjson = fixup_produces(oasjson)

    // parse generated OAS
    model = await oas.parse(oasjson)

    // await model.getDeclarationByName('Base64').withFormat("byte")
    // oasyaml = await oas.generateYamlString(model)
    // model = await oas.parseYaml(oasyaml)

    fs.writeFileSync(out_path, oasjson)

    // validate OAS parser model
    report = await oas.validate(model)
    console.log('###################################')
    console.log('OAS validation report:\n', report.toString())
    if (!report.conforms) {
      failed = true
    }

    // parse generated OAS
    model = await oas.parse(oasjson)

    // resolve model
    resolved = await oas.resolve(model)
    oasjson = await oas.generateString(resolved)
    fs.writeFileSync(out_path_resolved, oasjson)

    // parse generated resolved OAS
    model = await oas.parse(oasjson)

    // validate OAS parser model
    report = await oas.validate(model)
    console.log('###################################')
    console.log('Resolved OAS validation report:\n', report.toString())
    if (!report.conforms) {
      failed = true
    }

  } catch(err) {
    console.log('Error:\n', err)
    failed = true
  }
  if (failed) {
    process.exitCode = 1
  }
}
main()
