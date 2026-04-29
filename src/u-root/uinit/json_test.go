package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/google/jsonschema-go/jsonschema"
)

func testSchemaWith[T any](t *testing.T, sample T, schemaPath string) {
	t.Helper()

	data, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("cannot generate JSON: %v", err)
	}

	var unmarshaled map[string]any
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("cannot unmarshal JSON")
	}

	schemaSource, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("cannot read schema: %s", schemaPath)
	}

	var schema jsonschema.Schema
	err = schema.UnmarshalJSON(schemaSource)
	if err != nil {
		t.Fatalf("cannot load schema %s: %s", schemaPath, err)
	}

	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatalf("cannot resolve schema %s: %s", schemaPath, err)
	}

	err = resolved.Validate(unmarshaled)
	if err != nil {
		t.Logf("JSON: %s", data)
		t.Logf("Value: %v", sample)
		t.Fatalf("failed to validate against %s: %s", schemaPath, err)
	}
}

func testSchema[T any](t *testing.T, schemaPath string) {
	var sample T
	_ = faker.FakeData(&sample)
	testSchemaWith(t, sample, schemaPath)
}

func testSchemaDiagnoseData(t *testing.T, schemaPath string) {
	// faker produces a null clusterLogs, which isn't actually valid
	logItem := map[string]any{"level": "warn", "msg": "test"}
	version := "3.6.0"
	exited := 1
	sample := diagnoseData{
		ClusterLogs: []clusterLogItem{logItem},
		ClusterSnapshot: &clusterSnapshot{
			Hash:      4,
			Revision:  5,
			TotalKey:  6,
			TotalSize: 7,
			Version:   &version,
		},
		ClusterState: clusterState{
			Exited:  &exited,
			Running: false,
		},
	}
	testSchemaWith(t, sample, schemaPath)
}

var tests = map[string]struct {
	f (func(t *testing.T, schemaPath string))
}{
	"platform_data": {testSchema[platformData]},
	"local_conf":    {testSchema[localConf]},
	"network":       {testSchema[Network]},
	"diagnose_data": {testSchemaDiagnoseData},
}

func TestSchemas(t *testing.T) {
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			test.f(t, "../../keyfender/test/"+name+".json")
		})
	}
}
