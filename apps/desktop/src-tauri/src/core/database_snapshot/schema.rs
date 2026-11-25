use sitecmd_protocol::engine_abi::{
    SchemaColumn, SchemaForeignKey, SchemaIndex, SchemaMigrationNames, SchemaSnapshot, SchemaSource,
};
use std::collections::HashSet;

pub(super) struct Table {
    pub(super) name: String,
    pub(super) columns: Vec<String>,
    pub(super) non_null_columns: HashSet<String>,
    pub(super) indexed_columns: HashSet<String>,
    pub(super) unique_index_groups: Vec<HashSet<String>>,
    pub(super) foreign_key_columns: HashSet<String>,
}

pub(super) fn schema(
    source: SchemaSource,
    tables: Vec<Table>,
    prisma: Option<HashSet<String>>,
    drizzle: Option<usize>,
) -> SchemaSnapshot {
    let mut schema = SchemaSnapshot {
        source: Some(Box::new(source)),
        migration_names: SchemaMigrationNames {
            prisma: prisma.map(sorted),
            drizzle_count: drizzle.map(|count| count as u64),
        },
        ..SchemaSnapshot::default()
    };
    for table in tables {
        schema.tables.push(table.name.clone());
        schema
            .columns
            .extend(table.columns.into_iter().map(|name| SchemaColumn {
                table: table.name.clone(),
                not_null: table.non_null_columns.contains(&name.to_ascii_lowercase()),
                name,
            }));
        let indexes = sorted(table.indexed_columns);
        if !indexes.is_empty() {
            schema.indexes.push(SchemaIndex {
                table: table.name.clone(),
                columns: indexes,
                unique: false,
            });
        }
        schema.indexes.extend(
            table
                .unique_index_groups
                .into_iter()
                .map(|columns| SchemaIndex {
                    table: table.name.clone(),
                    columns: sorted(columns),
                    unique: true,
                }),
        );
        schema
            .foreign_keys
            .extend(
                sorted(table.foreign_key_columns)
                    .into_iter()
                    .map(|column| SchemaForeignKey {
                        table: table.name.clone(),
                        column,
                    }),
            );
    }
    schema
}

fn sorted(values: HashSet<String>) -> Vec<String> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_unstable();
    values
}
