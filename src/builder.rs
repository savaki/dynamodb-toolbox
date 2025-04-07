use crate::table::Table;
use aws_sdk_dynamodb::types::{AttributeDefinition, KeySchemaElement, KeyType};
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
}

#[derive(Clone, Debug, Default)]
struct NoKeys;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Keys<T> {
    hash: T,
    range: Option<AttributeDefinitionBuilder>,
}

#[allow(dead_code)]
struct NoPK;

impl Keys<AttributeDefinitionBuilder> {
    pub fn hash_b(name: impl Into<String>) -> Keys<AttributeDefinitionBuilder> {
        Keys {
            hash: AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::B,
            },
            range: None,
        }
    }

    pub fn hash_n(name: impl Into<String>) -> Keys<AttributeDefinitionBuilder> {
        Keys {
            hash: AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::N,
            },
            range: None,
        }
    }

    pub fn hash_s(name: impl Into<String>) -> Keys<AttributeDefinitionBuilder> {
        Keys {
            hash: AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::S,
            },
            range: None,
        }
    }
}

impl<T> Keys<T> {
    pub fn range_b(self, name: impl Into<String>) -> Keys<T> {
        Keys {
            hash: self.hash,
            range: Some(AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::B,
            }),
        }
    }

    pub fn range_n(self, name: impl Into<String>) -> Keys<T> {
        Keys {
            hash: self.hash,
            range: Some(AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::N,
            }),
        }
    }

    pub fn range_s(self, name: impl Into<String>) -> Keys<T> {
        Keys {
            hash: self.hash,
            range: Some(AttributeDefinitionBuilder {
                attribute_name: name.into(),
                attribute_type: aws_sdk_dynamodb::types::ScalarAttributeType::S,
            }),
        }
    }
}

impl Keys<AttributeDefinitionBuilder> {
    pub fn build(
        self,
    ) -> Result<
        (AttributeDefinition, Option<AttributeDefinition>),
        aws_smithy_types::error::operation::BuildError,
    > {
        let hash = AttributeDefinition::builder()
            .attribute_name(self.hash.attribute_name)
            .attribute_type(self.hash.attribute_type)
            .build()?;

        let range = if let Some(range) = self.range {
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
        }
    }

    pub fn keys(
        self,
        keys: impl Into<Keys<AttributeDefinitionBuilder>>,
    ) -> Builder<N, Keys<AttributeDefinitionBuilder>> {
        Builder {
            table_name: self.table_name,
            keys: keys.into(),
        }
    }
}

impl Builder<NoName, Keys<AttributeDefinitionBuilder>> {
    pub async fn build(
        self,
        client: &Arc<aws_sdk_dynamodb::Client>,
    ) -> Result<Table, Box<dyn std::error::Error>> {
        let table_name = format!("table-{}", uuid::Uuid::new_v4());
        self.table_name(table_name).build(client).await
    }
}

impl Builder<Named, Keys<AttributeDefinitionBuilder>> {
    async fn build(
        self,
        client: &Arc<aws_sdk_dynamodb::Client>,
    ) -> Result<Table, Box<dyn std::error::Error>> {
        let table_name = self.table_name.0;
        println!("Creating table: {}", &table_name);

        let mut builder = client
            .create_table()
            .table_name(&table_name)
            .billing_mode(aws_sdk_dynamodb::types::BillingMode::PayPerRequest);

        let (pk, sk_opt) = self.keys.build()?;
        builder = builder
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(&pk.attribute_name)
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .attribute_definitions(pk);

        if let Some(sk) = sk_opt {
            builder = builder
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name(&sk.attribute_name)
                        .key_type(KeyType::Range)
                        .build()?,
                )
                .attribute_definitions(sk);
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

#[cfg(test)]
mod tests {
    use crate::builder::{Builder, Keys};
    use crate::table::TempTableFactory;

    #[tokio::test]
    async fn test_builder() {
        let subscriber = tracing_subscriber::FmtSubscriber::new();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global subscriber");

        let builder = Builder::new().keys(Keys::hash_s("pk").range_s("sk"));

        let mut factory = TempTableFactory::new().await;
        let _table = factory.create_table(builder).await.unwrap();
        factory.delete_tables().await.unwrap();
    }
}
