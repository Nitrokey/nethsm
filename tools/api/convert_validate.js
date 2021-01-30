const webapi = require('webapi-parser').WebApiParser
const raml = webapi.raml10
const oas = webapi.oas20
const fs = require('fs')
const in_path = '/dev/stdin'
const out_path = 'gen_nethsm_api_oas20.yaml'
const out_path_resolved = 'gen_nethsm_api_oas20_resolved.yaml'

async function main () {
  let failed = false
  try {
    // parse RAML
    model = await raml.parse('file://' + in_path)

    // validate RAML parser model
    report = await raml.validate(model)
    console.log('RAML validation report:\n', report.toString())
    if (!report.conforms) {
      failed = true
    }

    // parse RAML again
    model = await raml.parse('file://' + in_path)

    // convert to OAS
    oasyaml = await oas.generateYamlString(model)

    // patch some issues
    oasyaml = oasyaml.replace(/{host}/g, "nethsmdemo.nitrokey.com",)
    oasyaml = oasyaml.replace(/{version}/g, "v1")
    oasyaml = oasyaml.replace(/name: generated/g, "name: body")

    // parse generated OAS
    model = await oas.parseYaml(oasyaml)

    // await model.getDeclarationByName('Base64').withFormat("byte")
    // oasyaml = await oas.generateYamlString(model)
    // model = await oas.parseYaml(oasyaml)

    fs.writeFileSync(out_path, oasyaml)

    // validate OAS parser model
    report = await oas.validate(model)
    console.log('###################################')
    console.log('OAS validation report:\n', report.toString())
    if (!report.conforms) {
      failed = true
    }

    // parse generated OAS
    model = await oas.parseYaml(oasyaml)

    // resolve model
    resolved = await oas.resolve(model)
    oasyaml = await oas.generateYamlString(resolved)
    fs.writeFileSync(out_path_resolved, oasyaml)

    // parse generated resolved OAS
    model = await oas.parseYaml(oasyaml)

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
