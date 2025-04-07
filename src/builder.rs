use crate::table::Table;
use aws_sdk_dynamodb::types;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, GlobalSecondaryIndex, KeySchemaElement, KeyType, ProjectionType,
};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AttributeDefinitionBuilder {
    attribute_name: String,
    attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType,
}

#[derive(Clone, Debug, Default)]
pub struct Builder<N, K> {
    table_name: N,
    keys: K,
    gsi: Vec<GSIBuilder<Keys>>,
}

#[derive(Clone, Debug, Default)]
struct NoKeys;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Keys {
    hash_key: AttributeDefinitionBuilder,
    range_key: Option<AttributeDefinitionBuilder>,
}

#[allow(dead_code)]
struct NoPK;

impl Keys {
    pub fn hash_b(name: impl Into<String>) -> Keys {
        Keys {
            hash_key: AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::B,
            },
            range_key: None,
        }
    }

    pub fn hash_n(name: impl Into<String>) -> Keys {
        Keys {
            hash_key: AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::N,
            },
            range_key: None,
        }
    }

    pub fn hash_s(name: impl Into<String>) -> Keys {
        Keys {
            hash_key: AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::S,
            },
            range_key: None,
        }
    }

    pub fn range_b(self, name: impl Into<String>) -> Keys {
        Keys {
            hash_key: self.hash_key,
            range_key: Some(AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::B,
            }),
        }
    }

    pub fn range_n(self, name: impl Into<String>) -> Keys {
        Keys {
            hash_key: self.hash_key,
            range_key: Some(AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::N,
            }),
        }
    }

    pub fn range_s(self, name: impl Into<String>) -> Keys {
        Keys {
            hash_key: self.hash_key,
            range_key: Some(AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::S,
            }),
        }
    }
}

impl Keys {
    pub fn build(
        &self,
    ) -> Result<
        (AttributeDefinition, Option<AttributeDefinition>),
        aws_smithy_types::error::operation::BuildError,
    > {
        let keys = self.clone();
        let hash = AttributeDefinition::builder()
            .attribute_name(keys.hash_key.attribute_name)
            .attribute_type(keys.hash_key.attribute_type)
            .build()?;

        let range = if let Some(range) = keys.range_key {
            Some(
                AttributeDefinition::builder()
                    .attribute_name(range.attribute_name)
                    .attribute_type(range.attribute_type)
                    .build()?,
            )
        } else {
            None
        };

        Ok((hash, range))
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum Projection {
    All,
    KeysOnly,
    Include(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct GSIBuilder<K> {
    index_name: String,
    keys: K,
    projection: Projection,
}

impl<K> GSIBuilder<K> {
    pub fn keys(self, keys: impl Into<Keys>) -> GSIBuilder<Keys> {
        GSIBuilder {
            index_name: self.index_name,
            keys: keys.into(),
            projection: self.projection,
        }
    }

    pub fn project(self, projection: Projection) -> GSIBuilder<K> {
        GSIBuilder {
            index_name: self.index_name,
            keys: self.keys,
            projection,
        }
    }
}

impl GSIBuilder<NoKeys> {
    pub fn new(index_name: impl Into<String>) -> Self {
        Self {
            index_name: index_name.into(),
            keys: NoKeys,
            projection: Projection::KeysOnly,
        }
    }
}

impl GSIBuilder<Keys> {
    pub fn build(&self) -> Result<GlobalSecondaryIndex, Box<dyn std::error::Error>> {
        let index_name = self.index_name.clone();
        let mut builder = GlobalSecondaryIndex::builder()
            .index_name(index_name)
            .projection(
                types::Projection::builder()
                    .projection_type(ProjectionType::All)
                    .build(),
            );

        let (pk, sk_opt) = &self.keys.build()?;
        builder = builder.key_schema(
            KeySchemaElement::builder()
                .attribute_name(&pk.attribute_name)
                .key_type(KeyType::Hash)
                .build()?,
        );

        if let Some(sk) = sk_opt {
            builder = builder.key_schema(
                KeySchemaElement::builder()
                    .attribute_name(&sk.attribute_name)
                    .key_type(KeyType::Range)
                    .build()?,
            );
        }

        match &self.projection {
            Projection::All => {
                builder = builder.projection(
                    types::Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                );
            }
            Projection::KeysOnly => {
                builder = builder.projection(
                    types::Projection::builder()
                        .projection_type(ProjectionType::KeysOnly)
                        .build(),
                );
            }
            Projection::Include(attrs) => {
                let mut pb = types::Projection::builder().projection_type(ProjectionType::Include);

                for attr in attrs {
                    pb = pb.non_key_attributes(attr);
                }

                builder = builder.projection(pb.build());
            }
        }

        Ok(builder.build()?)
    }

    pub fn definitions(&self) -> Result<Vec<AttributeDefinition>, Box<dyn std::error::Error>> {
        let (pk, sk_opt) = self.keys.build()?;

        let mut definitions = vec![pk];
        if let Some(sk) = sk_opt {
            definitions.push(sk);
        }

        Ok(definitions)
    }
}

#[derive(Clone, Debug, Default)]
pub struct NoName;

#[derive(Clone, Debug, Default)]
pub struct Named(String);

impl Builder<NoName, NoKeys> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<N, K> Builder<N, K> {
    pub fn table_name(self, name: impl Into<String>) -> Builder<Named, K> {
        Builder {
            table_name: Named(name.into()),
            keys: self.keys,
            gsi: self.gsi,
        }
    }

    pub fn gsi(mut self, gsi: impl Into<GSIBuilder<Keys>>) -> Builder<N, K> {
        self.gsi.push(gsi.into());
        self
    }

    pub fn keys(self, keys: impl Into<Keys>) -> Builder<N, Keys> {
        Builder {
            table_name: self.table_name,
            keys: keys.into(),
            gsi: self.gsi,
        }
    }
}

impl Builder<NoName, Keys> {
    pub async fn build(
        self,
        client: &Arc<aws_sdk_dynamodb::Client>,
    ) -> Result<Table, Box<dyn std::error::Error>> {
        let table_name = format!("table-{}", uuid::Uuid::new_v4());
        self.table_name(table_name).build(client).await
    }
}

impl Builder<Named, Keys> {
    async fn build(
        self,
        client: &Arc<aws_sdk_dynamodb::Client>,
    ) -> Result<Table, Box<dyn std::error::Error>> {
        let table_name = self.table_name.0;
        tracing::info!("creating table, {}", &table_name);

        let mut builder = client
            .create_table()
            .table_name(&table_name)
            .billing_mode(aws_sdk_dynamodb::types::BillingMode::PayPerRequest);

        let mut definitions: Vec<AttributeDefinition> = vec![];
        let (pk, sk_opt) = self.keys.build()?;
        builder = builder.key_schema(
            KeySchemaElement::builder()
                .attribute_name(&pk.attribute_name)
                .key_type(KeyType::Hash)
                .build()?,
        );
        definitions.push(pk);

        if let Some(sk) = sk_opt {
            builder = builder.key_schema(
                KeySchemaElement::builder()
                    .attribute_name(&sk.attribute_name)
                    .key_type(KeyType::Range)
                    .build()?,
            );
            definitions.push(sk);
        }

        for gsi in self.gsi {
            gsi.definitions()?.iter().for_each(|v| {
                definitions.push(v.clone());
            });
            builder = builder.global_secondary_indexes(gsi.build()?);
        }
        for def in unique(definitions) {
            builder = builder.attribute_definitions(def.clone());
        }
        let table = builder.send().await?;
        let Some(description) = table.table_description() else {
            return Err("Failed to create table".into());
        };

        let Some(table_name) = description.table_name() else {
            return Err("Failed to get table name".into());
        };

        Ok(Table::new(table_name, client))
    }
}

fn unique(strings: Vec<AttributeDefinition>) -> Vec<AttributeDefinition> {
    let mut seen = HashSet::new();
    strings
        .into_iter()
        .filter(|s| seen.insert(s.attribute_name().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::builder::{Builder, GSIBuilder, Keys, Projection};
    use crate::table::TempTableFactory;

    #[tokio::test]
    async fn test_builder() {
        let subscriber = tracing_subscriber::FmtSubscriber::new();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global subscriber");

        let builder = Builder::new().keys(Keys::hash_s("pk").range_s("sk")).gsi(
            GSIBuilder::new("gsi")
                .keys(Keys::hash_s("gsi_pk"))
                .project(Projection::Include(vec!["a".to_string(), "b".to_string()])),
        );

        let mut factory = TempTableFactory::new().await;
        let _table = factory.create_table(builder).await.unwrap();
        factory.delete_tables().await.unwrap();
    }
}
