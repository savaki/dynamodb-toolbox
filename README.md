dynamodb-toolbox
------------------------------------------------------------

`dynamodb-toolbox` provides utilities for working with DynamoDB, including a simple way to define and manage your data
models. 


### Example

```rust
    #[tokio::test]
    async fn test_builder() {
        let subscriber = tracing_subscriber::FmtSubscriber::new();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global subscriber");

        let builder = Builder::new().keys(Keys::hash_s("pk").range_s("sk"));

        // create temp table factory
        let mut factory = TempTableFactory::new().await;
        // create temp table
        let _table = factory.create_table(builder).await.unwrap();
  
        // ... your code here
  
        // delete any temp table created by the factory
        factory.delete_tables().await.unwrap();
    }
```
