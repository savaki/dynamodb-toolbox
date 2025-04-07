use crate::builder;
use crate::builder::{AttributeDefinitionBuilder, Keys, NoName};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::config::Credentials;
use aws_sdk_dynamodb::{Client, Config};
use aws_smithy_runtime_api::client::result::SdkError;
use builder::Builder;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Table {
    table_name: String,
    client: Arc<Client>,
}

type DeleteTableResult = Result<
    String,
    SdkError<
        aws_sdk_dynamodb::operation::delete_table::DeleteTableError,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
>;

impl Table {
    pub fn new(table_name: &str, client: &Arc<Client>) -> Self {
        Table {
            table_name: table_name.to_string(),
            client: client.clone(),
        }
    }

    pub async fn delete(self) -> DeleteTableResult {
        match self
            .client
            .delete_table()
            .table_name(&self.table_name)
            .send()
            .await
        {
            Ok(_) => Ok(self.table_name),
            Err(e) => {
                println!("Error deleting table: {}", e);
                Err(e)
            }
        }
    }
}

pub struct TempTable {
    table: Option<Table>,
}

impl TempTable {
    #[allow(dead_code)]
    pub fn table_name(&self) -> Option<String> {
        self.table.as_ref().map(|t| t.table_name.clone())
    }
}

#[allow(dead_code)]
pub struct TempTableFactory {
    client: Arc<Client>,
    cleanup: Vec<Pin<Box<dyn Future<Output = DeleteTableResult> + Send>>>,
}

impl TempTableFactory {
    #[allow(dead_code)]
    pub async fn new() -> Self {
        let region = RegionProviderChain::default_provider()
            .or_else("us-west-2")
            .region()
            .await;
        let config = Config::builder()
            .behavior_version_latest()
            .credentials_provider(Credentials::new("blah", "blah", None, None, "static"))
            .endpoint_url("http://localhost:8000")
            .region(region)
            .build();
        let client = Arc::new(Client::from_conf(config));
        TempTableFactory {
            client,
            cleanup: vec![],
        }
    }

    #[allow(dead_code)]
    pub async fn create_table(
        &mut self,
        builder: Builder<NoName, Keys<AttributeDefinitionBuilder>>,
    ) -> Result<TempTable, Box<dyn std::error::Error>> {
        let table = builder.build(&self.client).await?;
        let future = table.clone().delete();
        let pinned = Box::pin(future);
        self.cleanup.push(pinned);
        Ok(TempTable { table: Some(table) })
    }

    #[allow(dead_code)]
    pub async fn delete_tables(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut futures = vec![];
        for future in self.cleanup.drain(..) {
            futures.push(future);
        }
        let results = futures::future::join_all(futures).await;
        for result in results {
            match result {
                Ok(table_name) => tracing::info!("deleted table, {}", table_name),
                Err(e) => tracing::info!("failed to delete table: {:?}", e),
            }
        }
        Ok(())
    }
}
