use async_trait::async_trait;
use ipars_control_plane::customer_resources::{
    customer_project_page, public_service_page, reject_stale_status_observation,
    validate_customer_resource_cluster_id, validate_customer_resource_page_limit,
    CreateCustomerProject, CreatePublicService, CustomerAccount, CustomerAccountId,
    CustomerProject, CustomerProjectId, CustomerProjectPage, CustomerResourceError,
    CustomerResourceKind, CustomerResourceStore, EnsurePersonalAccount, KeycloakIdentity,
    KubernetesName, PublicServiceId, PublicServicePage, PublicServiceResource, PublicServiceStatus,
    MAX_CLUSTER_CUSTOMER_PROJECTS, MAX_CLUSTER_PUBLIC_SERVICES,
};
use ipars_control_plane::ControlPlaneError;
use ipars_types::ClusterId;
use sqlx::postgres::PgRow;
use sqlx::sqlite::SqliteRow;
use sqlx::{Executor, Postgres, Row, SqlitePool, Transaction};

use crate::{PostgresControlPlaneStore, SqliteControlPlaneStore};

pub(super) async fn migrate_sqlite_customer_resources(
    pool: &SqlitePool,
) -> Result<(), ControlPlaneError> {
    let mut transaction = pool.begin().await.map_err(super::sql_error)?;
    transaction
        .execute(
            r#"
            CREATE TABLE IF NOT EXISTS customer_accounts (
                cluster_id TEXT NOT NULL
                    CHECK(length(cluster_id) BETWEEN 1 AND 128),
                account_id TEXT NOT NULL
                    CHECK(length(account_id) = 37 AND substr(account_id, 1, 5) = 'acct_'),
                issuer TEXT NOT NULL
                    CHECK(length(issuer) BETWEEN 1 AND 2048),
                subject TEXT NOT NULL
                    CHECK(length(subject) BETWEEN 1 AND 255),
                max_projects INTEGER NOT NULL
                    CHECK(max_projects BETWEEN 0 AND 10000),
                max_public_services INTEGER NOT NULL
                    CHECK(max_public_services BETWEEN 0 AND 10000),
                record_json TEXT NOT NULL,
                PRIMARY KEY (cluster_id, account_id),
                CONSTRAINT customer_accounts_identity_unique
                    UNIQUE (cluster_id, issuer, subject)
            );
            "#,
        )
        .await
        .map_err(super::sql_error)?;
    transaction
        .execute(
            r#"
            CREATE TABLE IF NOT EXISTS customer_projects (
                cluster_id TEXT NOT NULL
                    CHECK(length(cluster_id) BETWEEN 1 AND 128),
                project_id TEXT NOT NULL
                    CHECK(length(project_id) = 36 AND substr(project_id, 1, 4) = 'prj_'),
                account_id TEXT NOT NULL
                    CHECK(length(account_id) = 37 AND substr(account_id, 1, 5) = 'acct_'),
                name TEXT NOT NULL
                    CHECK(length(name) BETWEEN 1 AND 63),
                kubernetes_namespace TEXT NOT NULL
                    CHECK(length(kubernetes_namespace) BETWEEN 1 AND 63),
                record_json TEXT NOT NULL,
                PRIMARY KEY (cluster_id, project_id),
                CONSTRAINT customer_projects_owner_name_unique
                    UNIQUE (cluster_id, account_id, name),
                CONSTRAINT customer_projects_namespace_unique
                    UNIQUE (cluster_id, kubernetes_namespace),
                CONSTRAINT customer_projects_owner_namespace_key_unique
                    UNIQUE (cluster_id, project_id, account_id, kubernetes_namespace),
                FOREIGN KEY (cluster_id, account_id)
                    REFERENCES customer_accounts(cluster_id, account_id)
                    ON DELETE CASCADE
            );
            "#,
        )
        .await
        .map_err(super::sql_error)?;
    transaction
        .execute(
            r#"
            CREATE TABLE IF NOT EXISTS customer_public_services (
                cluster_id TEXT NOT NULL
                    CHECK(length(cluster_id) BETWEEN 1 AND 128),
                resource_id TEXT NOT NULL
                    CHECK(length(resource_id) = 37 AND substr(resource_id, 1, 5) = 'psvc_'),
                account_id TEXT NOT NULL
                    CHECK(length(account_id) = 37 AND substr(account_id, 1, 5) = 'acct_'),
                project_id TEXT NOT NULL
                    CHECK(length(project_id) = 36 AND substr(project_id, 1, 4) = 'prj_'),
                name TEXT NOT NULL
                    CHECK(length(name) BETWEEN 1 AND 63),
                namespace TEXT NOT NULL
                    CHECK(length(namespace) BETWEEN 1 AND 63),
                generation INTEGER NOT NULL CHECK(generation >= 1),
                record_json TEXT NOT NULL,
                PRIMARY KEY (cluster_id, resource_id),
                CONSTRAINT customer_public_services_project_name_unique
                    UNIQUE (cluster_id, project_id, name),
                FOREIGN KEY (cluster_id, project_id, account_id, namespace)
                    REFERENCES customer_projects(
                        cluster_id, project_id, account_id, kubernetes_namespace
                    )
                    ON DELETE CASCADE
            );
            "#,
        )
        .await
        .map_err(super::sql_error)?;
    for statement in [
        r#"
        CREATE INDEX IF NOT EXISTS customer_projects_account_idx
        ON customer_projects(cluster_id, account_id, project_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS customer_public_services_project_idx
        ON customer_public_services(cluster_id, project_id, resource_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS customer_public_services_account_idx
        ON customer_public_services(cluster_id, account_id, resource_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS customer_public_services_desired_idx
        ON customer_public_services(cluster_id, resource_id, generation);
        "#,
    ] {
        transaction
            .execute(statement)
            .await
            .map_err(super::sql_error)?;
    }
    transaction.commit().await.map_err(super::sql_error)?;
    Ok(())
}

pub(super) async fn migrate_postgres_customer_resources(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ControlPlaneError> {
    transaction
        .execute(
            r#"
            CREATE TABLE IF NOT EXISTS customer_accounts (
                cluster_id TEXT NOT NULL
                    CHECK(length(cluster_id) BETWEEN 1 AND 128),
                account_id TEXT NOT NULL
                    CHECK(length(account_id) = 37 AND substr(account_id, 1, 5) = 'acct_'),
                issuer TEXT NOT NULL
                    CHECK(length(issuer) BETWEEN 1 AND 2048),
                subject TEXT NOT NULL
                    CHECK(length(subject) BETWEEN 1 AND 255),
                max_projects BIGINT NOT NULL
                    CHECK(max_projects BETWEEN 0 AND 10000),
                max_public_services BIGINT NOT NULL
                    CHECK(max_public_services BETWEEN 0 AND 10000),
                record_json JSONB NOT NULL,
                PRIMARY KEY (cluster_id, account_id),
                CONSTRAINT customer_accounts_identity_unique
                    UNIQUE (cluster_id, issuer, subject)
            );
            "#,
        )
        .await
        .map_err(super::sql_error)?;
    transaction
        .execute(
            r#"
            CREATE TABLE IF NOT EXISTS customer_projects (
                cluster_id TEXT NOT NULL
                    CHECK(length(cluster_id) BETWEEN 1 AND 128),
                project_id TEXT NOT NULL
                    CHECK(length(project_id) = 36 AND substr(project_id, 1, 4) = 'prj_'),
                account_id TEXT NOT NULL
                    CHECK(length(account_id) = 37 AND substr(account_id, 1, 5) = 'acct_'),
                name TEXT NOT NULL
                    CHECK(length(name) BETWEEN 1 AND 63),
                kubernetes_namespace TEXT NOT NULL
                    CHECK(length(kubernetes_namespace) BETWEEN 1 AND 63),
                record_json JSONB NOT NULL,
                PRIMARY KEY (cluster_id, project_id),
                CONSTRAINT customer_projects_owner_name_unique
                    UNIQUE (cluster_id, account_id, name),
                CONSTRAINT customer_projects_namespace_unique
                    UNIQUE (cluster_id, kubernetes_namespace),
                CONSTRAINT customer_projects_owner_namespace_key_unique
                    UNIQUE (cluster_id, project_id, account_id, kubernetes_namespace),
                CONSTRAINT customer_projects_account_fk
                    FOREIGN KEY (cluster_id, account_id)
                    REFERENCES customer_accounts(cluster_id, account_id)
                    ON DELETE CASCADE
            );
            "#,
        )
        .await
        .map_err(super::sql_error)?;
    transaction
        .execute(
            r#"
            CREATE TABLE IF NOT EXISTS customer_public_services (
                cluster_id TEXT NOT NULL
                    CHECK(length(cluster_id) BETWEEN 1 AND 128),
                resource_id TEXT NOT NULL
                    CHECK(length(resource_id) = 37 AND substr(resource_id, 1, 5) = 'psvc_'),
                account_id TEXT NOT NULL
                    CHECK(length(account_id) = 37 AND substr(account_id, 1, 5) = 'acct_'),
                project_id TEXT NOT NULL
                    CHECK(length(project_id) = 36 AND substr(project_id, 1, 4) = 'prj_'),
                name TEXT NOT NULL
                    CHECK(length(name) BETWEEN 1 AND 63),
                namespace TEXT NOT NULL
                    CHECK(length(namespace) BETWEEN 1 AND 63),
                generation BIGINT NOT NULL CHECK(generation >= 1),
                record_json JSONB NOT NULL,
                PRIMARY KEY (cluster_id, resource_id),
                CONSTRAINT customer_public_services_project_name_unique
                    UNIQUE (cluster_id, project_id, name),
                CONSTRAINT customer_public_services_project_fk
                    FOREIGN KEY (cluster_id, project_id, account_id, namespace)
                    REFERENCES customer_projects(
                        cluster_id, project_id, account_id, kubernetes_namespace
                    )
                    ON DELETE CASCADE
            );
            "#,
        )
        .await
        .map_err(super::sql_error)?;
    for statement in [
        r#"
        CREATE INDEX IF NOT EXISTS customer_projects_account_idx
        ON customer_projects(cluster_id, account_id, project_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS customer_public_services_project_idx
        ON customer_public_services(cluster_id, project_id, resource_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS customer_public_services_account_idx
        ON customer_public_services(cluster_id, account_id, resource_id);
        "#,
        r#"
        CREATE INDEX IF NOT EXISTS customer_public_services_desired_idx
        ON customer_public_services(cluster_id, resource_id, generation);
        "#,
    ] {
        transaction
            .execute(statement)
            .await
            .map_err(super::sql_error)?;
    }
    Ok(())
}

#[async_trait]
impl CustomerResourceStore for SqliteControlPlaneStore {
    async fn ensure_personal_account(
        &self,
        request: EnsurePersonalAccount,
    ) -> Result<CustomerAccount, CustomerResourceError> {
        request.validate()?;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(customer_sql_error)?;
        if let Some(account) =
            sqlite_account_by_identity(&mut transaction, &request.cluster_id, &request.identity)
                .await?
        {
            transaction.commit().await.map_err(customer_sql_error)?;
            return Ok(account);
        }

        let account = CustomerAccount {
            account_id: CustomerAccount::deterministic_id(&request.cluster_id, &request.identity)?,
            cluster_id: request.cluster_id,
            identity: request.identity,
            quota: request.quota,
            created_at: request.created_at,
        };
        account.validate()?;
        sqlx::query(
            r#"
            INSERT INTO customer_accounts (
                cluster_id, account_id, issuer, subject, max_projects,
                max_public_services, record_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(account.cluster_id.as_str())
        .bind(account.account_id.as_str())
        .bind(account.identity.issuer())
        .bind(account.identity.subject())
        .bind(i64::from(account.quota.max_projects))
        .bind(i64::from(account.quota.max_public_services))
        .bind(sqlite_account_json(&account)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| account_insert_error(error, &account))?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(account)
    }

    async fn get_personal_account(
        &self,
        cluster_id: &ClusterId,
        identity: &KeycloakIdentity,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        identity.validate()?;
        let row = sqlx::query(
            r#"
            SELECT cluster_id, account_id, issuer, subject, max_projects,
                   max_public_services, record_json
            FROM customer_accounts
            WHERE cluster_id = ?1 AND issuer = ?2 AND subject = ?3
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(identity.issuer())
        .bind(identity.subject())
        .fetch_optional(&self.pool)
        .await
        .map_err(customer_sql_error)?;
        row.map(sqlite_row_to_account).transpose()
    }

    async fn get_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let row = sqlx::query(
            r#"
            SELECT cluster_id, account_id, issuer, subject, max_projects,
                   max_public_services, record_json
            FROM customer_accounts
            WHERE cluster_id = ?1 AND account_id = ?2
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(account_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(customer_sql_error)?;
        row.map(sqlite_row_to_account).transpose()
    }

    async fn delete_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<bool, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(customer_sql_error)?;
        sqlx::query(
            "DELETE FROM customer_public_services WHERE cluster_id = ?1 AND account_id = ?2",
        )
        .bind(cluster_id.as_str())
        .bind(account_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        sqlx::query("DELETE FROM customer_projects WHERE cluster_id = ?1 AND account_id = ?2")
            .bind(cluster_id.as_str())
            .bind(account_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(customer_sql_error)?;
        let result =
            sqlx::query("DELETE FROM customer_accounts WHERE cluster_id = ?1 AND account_id = ?2")
                .bind(cluster_id.as_str())
                .bind(account_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(customer_sql_error)?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn create_customer_project(
        &self,
        request: CreateCustomerProject,
    ) -> Result<CustomerProject, CustomerResourceError> {
        request.validate()?;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(customer_sql_error)?;
        let account =
            sqlite_account_by_id(&mut transaction, &request.cluster_id, &request.account_id)
                .await?
                .ok_or_else(|| account_not_found(&request.cluster_id, &request.account_id))?;
        let duplicate = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_projects
            WHERE cluster_id = ?1 AND account_id = ?2 AND name = ?3
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.account_id.as_str())
        .bind(request.name.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if duplicate != 0 {
            return Err(duplicate_name(CustomerResourceKind::Project, request.name));
        }
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_projects
            WHERE cluster_id = ?1 AND account_id = ?2
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.account_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if count >= i64::from(account.quota.max_projects) {
            return Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::Project,
                limit: account.quota.max_projects,
            });
        }
        let cluster_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM customer_projects WHERE cluster_id = ?1",
        )
        .bind(request.cluster_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if cluster_count >= MAX_CLUSTER_CUSTOMER_PROJECTS as i64 {
            return Err(CustomerResourceError::ClusterCapacityExceeded {
                kind: CustomerResourceKind::Project,
                limit: MAX_CLUSTER_CUSTOMER_PROJECTS,
            });
        }

        let project = make_project(request)?;
        sqlx::query(
            r#"
            INSERT INTO customer_projects (
                cluster_id, project_id, account_id, name,
                kubernetes_namespace, record_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(project.cluster_id.as_str())
        .bind(project.project_id.as_str())
        .bind(project.account_id.as_str())
        .bind(project.name.as_str())
        .bind(project.kubernetes_namespace.as_str())
        .bind(sqlite_project_json(&project)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| project_insert_error(error, &project))?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(project)
    }

    async fn get_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerProject>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let project = sqlite_project_by_id(&self.pool, cluster_id, project_id).await?;
        if let Some(project) = &project {
            ensure_project_owner(project, account_id)?;
        }
        Ok(project)
    }

    async fn get_project_owner(
        &self,
        cluster_id: &ClusterId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let Some(project) = sqlite_project_by_id(&self.pool, cluster_id, project_id).await? else {
            return Ok(None);
        };
        self.get_customer_account(cluster_id, &project.account_id)
            .await?
            .map(Some)
            .ok_or_else(|| {
                CustomerResourceError::Store(
                    "customer project points to a missing account".to_string(),
                )
            })
    }

    async fn list_customer_projects(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        if self
            .get_customer_account(cluster_id, account_id)
            .await?
            .is_none()
        {
            return Err(account_not_found(cluster_id, account_id));
        }
        sqlx::query(
            r#"
            SELECT cluster_id, project_id, account_id, name,
                   kubernetes_namespace, record_json
            FROM customer_projects
            WHERE cluster_id = ?1 AND account_id = ?2
              AND project_id > COALESCE(?3, '')
            ORDER BY project_id
            LIMIT ?4
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(account_id.as_str())
        .bind(after.map(CustomerProjectId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(sqlite_row_to_project)
        .collect::<Result<Vec<_>, _>>()
        .map(|projects| customer_project_page(projects, limit))
    }

    async fn list_desired_customer_projects(
        &self,
        cluster_id: &ClusterId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        sqlx::query(
            r#"
            SELECT cluster_id, project_id, account_id, name,
                   kubernetes_namespace, record_json
            FROM customer_projects
            WHERE cluster_id = ?1
              AND project_id > COALESCE(?2, '')
            ORDER BY project_id
            LIMIT ?3
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(after.map(CustomerProjectId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(sqlite_row_to_project)
        .collect::<Result<Vec<_>, _>>()
        .map(|projects| customer_project_page(projects, limit))
    }

    async fn delete_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<bool, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(customer_sql_error)?;
        let Some(project) = sqlite_project_by_id(&mut *transaction, cluster_id, project_id).await?
        else {
            transaction.commit().await.map_err(customer_sql_error)?;
            return Ok(false);
        };
        ensure_project_owner(&project, account_id)?;
        sqlx::query(
            "DELETE FROM customer_public_services WHERE cluster_id = ?1 AND project_id = ?2",
        )
        .bind(cluster_id.as_str())
        .bind(project_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        let result =
            sqlx::query("DELETE FROM customer_projects WHERE cluster_id = ?1 AND project_id = ?2")
                .bind(cluster_id.as_str())
                .bind(project_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(customer_sql_error)?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn create_public_service(
        &self,
        request: CreatePublicService,
    ) -> Result<PublicServiceResource, CustomerResourceError> {
        request.validate()?;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(customer_sql_error)?;
        let account =
            sqlite_account_by_id(&mut transaction, &request.cluster_id, &request.account_id)
                .await?
                .ok_or_else(|| account_not_found(&request.cluster_id, &request.account_id))?;
        let project =
            sqlite_project_by_id(&mut *transaction, &request.cluster_id, &request.project_id)
                .await?
                .ok_or_else(|| project_not_found(&request.cluster_id, &request.project_id))?;
        ensure_project_owner(&project, &request.account_id)?;
        let duplicate = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_public_services
            WHERE cluster_id = ?1 AND project_id = ?2 AND name = ?3
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.project_id.as_str())
        .bind(request.name.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if duplicate != 0 {
            return Err(duplicate_name(
                CustomerResourceKind::PublicService,
                request.name,
            ));
        }
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_public_services
            WHERE cluster_id = ?1 AND account_id = ?2
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.account_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if count >= i64::from(account.quota.max_public_services) {
            return Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: account.quota.max_public_services,
            });
        }
        let cluster_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM customer_public_services WHERE cluster_id = ?1",
        )
        .bind(request.cluster_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if cluster_count >= MAX_CLUSTER_PUBLIC_SERVICES as i64 {
            return Err(CustomerResourceError::ClusterCapacityExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: MAX_CLUSTER_PUBLIC_SERVICES,
            });
        }

        let resource = make_public_service(request, &project)?;
        sqlx::query(
            r#"
            INSERT INTO customer_public_services (
                cluster_id, resource_id, account_id, project_id,
                name, namespace, generation, record_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(resource.cluster_id.as_str())
        .bind(resource.resource_id.as_str())
        .bind(resource.account_id.as_str())
        .bind(resource.project_id.as_str())
        .bind(resource.name.as_str())
        .bind(resource.namespace.as_str())
        .bind(generation_to_i64(resource.generation)?)
        .bind(sqlite_public_service_json(&resource)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| public_service_insert_error(error, &resource))?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(resource)
    }

    async fn get_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<Option<PublicServiceResource>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let resource = sqlite_public_service_by_id(&self.pool, cluster_id, resource_id).await?;
        if let Some(resource) = &resource {
            ensure_public_service_owner(resource, account_id, project_id)?;
        }
        Ok(resource)
    }

    async fn list_public_services(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        let project = sqlite_project_by_id(&self.pool, cluster_id, project_id)
            .await?
            .ok_or_else(|| project_not_found(cluster_id, project_id))?;
        ensure_project_owner(&project, account_id)?;
        sqlx::query(
            r#"
            SELECT cluster_id, resource_id, account_id, project_id,
                   name, namespace, generation, record_json
            FROM customer_public_services
            WHERE cluster_id = ?1 AND project_id = ?2
              AND resource_id > COALESCE(?3, '')
            ORDER BY resource_id
            LIMIT ?4
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(project_id.as_str())
        .bind(after.map(PublicServiceId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(sqlite_row_to_public_service)
        .collect::<Result<Vec<_>, _>>()
        .map(|public_services| public_service_page(public_services, limit))
    }

    async fn delete_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<bool, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(customer_sql_error)?;
        let Some(resource) =
            sqlite_public_service_by_id(&mut *transaction, cluster_id, resource_id).await?
        else {
            transaction.commit().await.map_err(customer_sql_error)?;
            return Ok(false);
        };
        ensure_public_service_owner(&resource, account_id, project_id)?;
        let result = sqlx::query(
            "DELETE FROM customer_public_services WHERE cluster_id = ?1 AND resource_id = ?2",
        )
        .bind(cluster_id.as_str())
        .bind(resource_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_desired_public_services(
        &self,
        cluster_id: &ClusterId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        sqlx::query(
            r#"
            SELECT cluster_id, resource_id, account_id, project_id,
                   name, namespace, generation, record_json
            FROM customer_public_services
            WHERE cluster_id = ?1
              AND resource_id > COALESCE(?2, '')
            ORDER BY resource_id
            LIMIT ?3
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(after.map(PublicServiceId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(sqlite_row_to_public_service)
        .collect::<Result<Vec<_>, _>>()
        .map(|public_services| public_service_page(public_services, limit))
    }

    async fn update_public_service_status(
        &self,
        cluster_id: &ClusterId,
        resource_id: &PublicServiceId,
        expected_generation: u64,
        status: PublicServiceStatus,
    ) -> Result<PublicServiceResource, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(customer_sql_error)?;
        let mut resource = sqlite_public_service_by_id(&mut *transaction, cluster_id, resource_id)
            .await?
            .ok_or_else(|| public_service_not_found(cluster_id, resource_id))?;
        if resource.generation != expected_generation {
            return Err(generation_conflict(
                resource_id,
                expected_generation,
                resource.generation,
            ));
        }
        status.validate_for_update(
            expected_generation,
            resource.spec.public_port,
            chrono::Utc::now(),
        )?;
        let observed_at = status.observed_at.ok_or_else(|| {
            CustomerResourceError::Store(
                "validated status update has no observation time".to_string(),
            )
        })?;
        reject_stale_status_observation(&resource, resource_id, observed_at)?;
        resource.updated_at = observed_at;
        resource.status = status;
        resource.validate()?;
        let result = sqlx::query(
            r#"
            UPDATE customer_public_services
            SET record_json = ?1
            WHERE cluster_id = ?2 AND resource_id = ?3 AND generation = ?4
            "#,
        )
        .bind(sqlite_public_service_json(&resource)?)
        .bind(cluster_id.as_str())
        .bind(resource_id.as_str())
        .bind(generation_to_i64(expected_generation)?)
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if result.rows_affected() != 1 {
            return Err(generation_conflict(
                resource_id,
                expected_generation,
                resource.generation,
            ));
        }
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(resource)
    }
}

async fn sqlite_account_by_identity(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    cluster_id: &ClusterId,
    identity: &KeycloakIdentity,
) -> Result<Option<CustomerAccount>, CustomerResourceError> {
    let row = sqlx::query(
        r#"
        SELECT cluster_id, account_id, issuer, subject, max_projects,
               max_public_services, record_json
        FROM customer_accounts
        WHERE cluster_id = ?1 AND issuer = ?2 AND subject = ?3
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(identity.issuer())
    .bind(identity.subject())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(customer_sql_error)?;
    row.map(sqlite_row_to_account).transpose()
}

async fn sqlite_account_by_id(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    cluster_id: &ClusterId,
    account_id: &CustomerAccountId,
) -> Result<Option<CustomerAccount>, CustomerResourceError> {
    let row = sqlx::query(
        r#"
        SELECT cluster_id, account_id, issuer, subject, max_projects,
               max_public_services, record_json
        FROM customer_accounts
        WHERE cluster_id = ?1 AND account_id = ?2
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(account_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(customer_sql_error)?;
    row.map(sqlite_row_to_account).transpose()
}

async fn sqlite_project_by_id<'e, E>(
    executor: E,
    cluster_id: &ClusterId,
    project_id: &CustomerProjectId,
) -> Result<Option<CustomerProject>, CustomerResourceError>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query(
        r#"
        SELECT cluster_id, project_id, account_id, name,
               kubernetes_namespace, record_json
        FROM customer_projects
        WHERE cluster_id = ?1 AND project_id = ?2
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(project_id.as_str())
    .fetch_optional(executor)
    .await
    .map_err(customer_sql_error)?;
    row.map(sqlite_row_to_project).transpose()
}

async fn sqlite_public_service_by_id<'e, E>(
    executor: E,
    cluster_id: &ClusterId,
    resource_id: &PublicServiceId,
) -> Result<Option<PublicServiceResource>, CustomerResourceError>
where
    E: Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query(
        r#"
        SELECT cluster_id, resource_id, account_id, project_id,
               name, namespace, generation, record_json
        FROM customer_public_services
        WHERE cluster_id = ?1 AND resource_id = ?2
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(resource_id.as_str())
    .fetch_optional(executor)
    .await
    .map_err(customer_sql_error)?;
    row.map(sqlite_row_to_public_service).transpose()
}

async fn postgres_lock_customer_capacity(
    transaction: &mut Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
) -> Result<(), CustomerResourceError> {
    let lock_name = format!("heteronetwork-customer-resource-capacity:{cluster_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(lock_name)
        .execute(&mut **transaction)
        .await
        .map_err(customer_sql_error)?;
    Ok(())
}

#[async_trait]
impl CustomerResourceStore for PostgresControlPlaneStore {
    async fn ensure_personal_account(
        &self,
        request: EnsurePersonalAccount,
    ) -> Result<CustomerAccount, CustomerResourceError> {
        request.validate()?;
        let account = CustomerAccount {
            account_id: CustomerAccount::deterministic_id(&request.cluster_id, &request.identity)?,
            cluster_id: request.cluster_id,
            identity: request.identity,
            quota: request.quota,
            created_at: request.created_at,
        };
        account.validate()?;
        let mut transaction = self.pool.begin().await.map_err(customer_sql_error)?;
        sqlx::query(
            r#"
            INSERT INTO customer_accounts (
                cluster_id, account_id, issuer, subject, max_projects,
                max_public_services, record_json
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT ON CONSTRAINT customer_accounts_identity_unique DO NOTHING
            "#,
        )
        .bind(account.cluster_id.as_str())
        .bind(account.account_id.as_str())
        .bind(account.identity.issuer())
        .bind(account.identity.subject())
        .bind(i64::from(account.quota.max_projects))
        .bind(i64::from(account.quota.max_public_services))
        .bind(postgres_account_json(&account)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| account_insert_error(error, &account))?;
        let stored = postgres_account_by_identity_for_update(
            &mut transaction,
            &account.cluster_id,
            &account.identity,
        )
        .await?
        .ok_or_else(|| {
            CustomerResourceError::Store(
                "personal account upsert did not produce a stored account".to_string(),
            )
        })?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(stored)
    }

    async fn get_personal_account(
        &self,
        cluster_id: &ClusterId,
        identity: &KeycloakIdentity,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        identity.validate()?;
        let row = sqlx::query(
            r#"
            SELECT cluster_id, account_id, issuer, subject, max_projects,
                   max_public_services, record_json
            FROM customer_accounts
            WHERE cluster_id = $1 AND issuer = $2 AND subject = $3
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(identity.issuer())
        .bind(identity.subject())
        .fetch_optional(&self.pool)
        .await
        .map_err(customer_sql_error)?;
        row.map(postgres_row_to_account).transpose()
    }

    async fn get_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let row = sqlx::query(
            r#"
            SELECT cluster_id, account_id, issuer, subject, max_projects,
                   max_public_services, record_json
            FROM customer_accounts
            WHERE cluster_id = $1 AND account_id = $2
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(account_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(customer_sql_error)?;
        row.map(postgres_row_to_account).transpose()
    }

    async fn delete_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<bool, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self.pool.begin().await.map_err(customer_sql_error)?;
        let Some(_) =
            postgres_account_by_id_for_update(&mut transaction, cluster_id, account_id).await?
        else {
            transaction.commit().await.map_err(customer_sql_error)?;
            return Ok(false);
        };
        sqlx::query(
            "DELETE FROM customer_public_services WHERE cluster_id = $1 AND account_id = $2",
        )
        .bind(cluster_id.as_str())
        .bind(account_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        sqlx::query("DELETE FROM customer_projects WHERE cluster_id = $1 AND account_id = $2")
            .bind(cluster_id.as_str())
            .bind(account_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(customer_sql_error)?;
        let result =
            sqlx::query("DELETE FROM customer_accounts WHERE cluster_id = $1 AND account_id = $2")
                .bind(cluster_id.as_str())
                .bind(account_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(customer_sql_error)?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn create_customer_project(
        &self,
        request: CreateCustomerProject,
    ) -> Result<CustomerProject, CustomerResourceError> {
        request.validate()?;
        let mut transaction = self.pool.begin().await.map_err(customer_sql_error)?;
        postgres_lock_customer_capacity(&mut transaction, &request.cluster_id).await?;
        let account = postgres_account_by_id_for_update(
            &mut transaction,
            &request.cluster_id,
            &request.account_id,
        )
        .await?
        .ok_or_else(|| account_not_found(&request.cluster_id, &request.account_id))?;
        let duplicate = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_projects
            WHERE cluster_id = $1 AND account_id = $2 AND name = $3
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.account_id.as_str())
        .bind(request.name.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if duplicate != 0 {
            return Err(duplicate_name(CustomerResourceKind::Project, request.name));
        }
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_projects
            WHERE cluster_id = $1 AND account_id = $2
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.account_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if count >= i64::from(account.quota.max_projects) {
            return Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::Project,
                limit: account.quota.max_projects,
            });
        }
        let cluster_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM customer_projects WHERE cluster_id = $1",
        )
        .bind(request.cluster_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if cluster_count >= MAX_CLUSTER_CUSTOMER_PROJECTS as i64 {
            return Err(CustomerResourceError::ClusterCapacityExceeded {
                kind: CustomerResourceKind::Project,
                limit: MAX_CLUSTER_CUSTOMER_PROJECTS,
            });
        }

        let project = make_project(request)?;
        sqlx::query(
            r#"
            INSERT INTO customer_projects (
                cluster_id, project_id, account_id, name,
                kubernetes_namespace, record_json
            ) VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(project.cluster_id.as_str())
        .bind(project.project_id.as_str())
        .bind(project.account_id.as_str())
        .bind(project.name.as_str())
        .bind(project.kubernetes_namespace.as_str())
        .bind(postgres_project_json(&project)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| project_insert_error(error, &project))?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(project)
    }

    async fn get_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerProject>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let project = postgres_project_by_id(&self.pool, cluster_id, project_id).await?;
        if let Some(project) = &project {
            ensure_project_owner(project, account_id)?;
        }
        Ok(project)
    }

    async fn get_project_owner(
        &self,
        cluster_id: &ClusterId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let Some(project) = postgres_project_by_id(&self.pool, cluster_id, project_id).await?
        else {
            return Ok(None);
        };
        self.get_customer_account(cluster_id, &project.account_id)
            .await?
            .map(Some)
            .ok_or_else(|| {
                CustomerResourceError::Store(
                    "customer project points to a missing account".to_string(),
                )
            })
    }

    async fn list_customer_projects(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        if self
            .get_customer_account(cluster_id, account_id)
            .await?
            .is_none()
        {
            return Err(account_not_found(cluster_id, account_id));
        }
        sqlx::query(
            r#"
            SELECT cluster_id, project_id, account_id, name,
                   kubernetes_namespace, record_json
            FROM customer_projects
            WHERE cluster_id = $1 AND account_id = $2
              AND project_id > COALESCE($3, '')
            ORDER BY project_id
            LIMIT $4
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(account_id.as_str())
        .bind(after.map(CustomerProjectId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(postgres_row_to_project)
        .collect::<Result<Vec<_>, _>>()
        .map(|projects| customer_project_page(projects, limit))
    }

    async fn list_desired_customer_projects(
        &self,
        cluster_id: &ClusterId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        sqlx::query(
            r#"
            SELECT cluster_id, project_id, account_id, name,
                   kubernetes_namespace, record_json
            FROM customer_projects
            WHERE cluster_id = $1
              AND project_id > COALESCE($2, '')
            ORDER BY project_id
            LIMIT $3
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(after.map(CustomerProjectId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(postgres_row_to_project)
        .collect::<Result<Vec<_>, _>>()
        .map(|projects| customer_project_page(projects, limit))
    }

    async fn delete_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<bool, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self.pool.begin().await.map_err(customer_sql_error)?;
        let Some(project) =
            postgres_project_by_id_for_update(&mut transaction, cluster_id, project_id).await?
        else {
            transaction.commit().await.map_err(customer_sql_error)?;
            return Ok(false);
        };
        ensure_project_owner(&project, account_id)?;
        sqlx::query(
            "DELETE FROM customer_public_services WHERE cluster_id = $1 AND project_id = $2",
        )
        .bind(cluster_id.as_str())
        .bind(project_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        let result =
            sqlx::query("DELETE FROM customer_projects WHERE cluster_id = $1 AND project_id = $2")
                .bind(cluster_id.as_str())
                .bind(project_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(customer_sql_error)?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn create_public_service(
        &self,
        request: CreatePublicService,
    ) -> Result<PublicServiceResource, CustomerResourceError> {
        request.validate()?;
        let mut transaction = self.pool.begin().await.map_err(customer_sql_error)?;
        postgres_lock_customer_capacity(&mut transaction, &request.cluster_id).await?;
        let account = postgres_account_by_id_for_update(
            &mut transaction,
            &request.cluster_id,
            &request.account_id,
        )
        .await?
        .ok_or_else(|| account_not_found(&request.cluster_id, &request.account_id))?;
        let project = postgres_project_by_id_for_update(
            &mut transaction,
            &request.cluster_id,
            &request.project_id,
        )
        .await?
        .ok_or_else(|| project_not_found(&request.cluster_id, &request.project_id))?;
        ensure_project_owner(&project, &request.account_id)?;
        let duplicate = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_public_services
            WHERE cluster_id = $1 AND project_id = $2 AND name = $3
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.project_id.as_str())
        .bind(request.name.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if duplicate != 0 {
            return Err(duplicate_name(
                CustomerResourceKind::PublicService,
                request.name,
            ));
        }
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM customer_public_services
            WHERE cluster_id = $1 AND account_id = $2
            "#,
        )
        .bind(request.cluster_id.as_str())
        .bind(request.account_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if count >= i64::from(account.quota.max_public_services) {
            return Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: account.quota.max_public_services,
            });
        }
        let cluster_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM customer_public_services WHERE cluster_id = $1",
        )
        .bind(request.cluster_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if cluster_count >= MAX_CLUSTER_PUBLIC_SERVICES as i64 {
            return Err(CustomerResourceError::ClusterCapacityExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: MAX_CLUSTER_PUBLIC_SERVICES,
            });
        }

        let resource = make_public_service(request, &project)?;
        sqlx::query(
            r#"
            INSERT INTO customer_public_services (
                cluster_id, resource_id, account_id, project_id,
                name, namespace, generation, record_json
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(resource.cluster_id.as_str())
        .bind(resource.resource_id.as_str())
        .bind(resource.account_id.as_str())
        .bind(resource.project_id.as_str())
        .bind(resource.name.as_str())
        .bind(resource.namespace.as_str())
        .bind(generation_to_i64(resource.generation)?)
        .bind(postgres_public_service_json(&resource)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| public_service_insert_error(error, &resource))?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(resource)
    }

    async fn get_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<Option<PublicServiceResource>, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let resource = postgres_public_service_by_id(&self.pool, cluster_id, resource_id).await?;
        if let Some(resource) = &resource {
            ensure_public_service_owner(resource, account_id, project_id)?;
        }
        Ok(resource)
    }

    async fn list_public_services(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        let project = postgres_project_by_id(&self.pool, cluster_id, project_id)
            .await?
            .ok_or_else(|| project_not_found(cluster_id, project_id))?;
        ensure_project_owner(&project, account_id)?;
        sqlx::query(
            r#"
            SELECT cluster_id, resource_id, account_id, project_id,
                   name, namespace, generation, record_json
            FROM customer_public_services
            WHERE cluster_id = $1 AND project_id = $2
              AND resource_id > COALESCE($3, '')
            ORDER BY resource_id
            LIMIT $4
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(project_id.as_str())
        .bind(after.map(PublicServiceId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(postgres_row_to_public_service)
        .collect::<Result<Vec<_>, _>>()
        .map(|public_services| public_service_page(public_services, limit))
    }

    async fn delete_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<bool, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self.pool.begin().await.map_err(customer_sql_error)?;
        let Some(resource) =
            postgres_public_service_by_id_for_update(&mut transaction, cluster_id, resource_id)
                .await?
        else {
            transaction.commit().await.map_err(customer_sql_error)?;
            return Ok(false);
        };
        ensure_public_service_owner(&resource, account_id, project_id)?;
        let result = sqlx::query(
            "DELETE FROM customer_public_services WHERE cluster_id = $1 AND resource_id = $2",
        )
        .bind(cluster_id.as_str())
        .bind(resource_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_desired_public_services(
        &self,
        cluster_id: &ClusterId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        validate_customer_resource_page_limit(limit)?;
        sqlx::query(
            r#"
            SELECT cluster_id, resource_id, account_id, project_id,
                   name, namespace, generation, record_json
            FROM customer_public_services
            WHERE cluster_id = $1
              AND resource_id > COALESCE($2, '')
            ORDER BY resource_id
            LIMIT $3
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(after.map(PublicServiceId::as_str))
        .bind(page_fetch_limit(limit)?)
        .fetch_all(&self.pool)
        .await
        .map_err(customer_sql_error)?
        .into_iter()
        .map(postgres_row_to_public_service)
        .collect::<Result<Vec<_>, _>>()
        .map(|public_services| public_service_page(public_services, limit))
    }

    async fn update_public_service_status(
        &self,
        cluster_id: &ClusterId,
        resource_id: &PublicServiceId,
        expected_generation: u64,
        status: PublicServiceStatus,
    ) -> Result<PublicServiceResource, CustomerResourceError> {
        validate_customer_resource_cluster_id(cluster_id)?;
        let mut transaction = self.pool.begin().await.map_err(customer_sql_error)?;
        let mut resource =
            postgres_public_service_by_id_for_update(&mut transaction, cluster_id, resource_id)
                .await?
                .ok_or_else(|| public_service_not_found(cluster_id, resource_id))?;
        if resource.generation != expected_generation {
            return Err(generation_conflict(
                resource_id,
                expected_generation,
                resource.generation,
            ));
        }
        status.validate_for_update(
            expected_generation,
            resource.spec.public_port,
            chrono::Utc::now(),
        )?;
        let observed_at = status.observed_at.ok_or_else(|| {
            CustomerResourceError::Store(
                "validated status update has no observation time".to_string(),
            )
        })?;
        reject_stale_status_observation(&resource, resource_id, observed_at)?;
        resource.updated_at = observed_at;
        resource.status = status;
        resource.validate()?;
        let result = sqlx::query(
            r#"
            UPDATE customer_public_services
            SET record_json = $1
            WHERE cluster_id = $2 AND resource_id = $3 AND generation = $4
            "#,
        )
        .bind(postgres_public_service_json(&resource)?)
        .bind(cluster_id.as_str())
        .bind(resource_id.as_str())
        .bind(generation_to_i64(expected_generation)?)
        .execute(&mut *transaction)
        .await
        .map_err(customer_sql_error)?;
        if result.rows_affected() != 1 {
            return Err(generation_conflict(
                resource_id,
                expected_generation,
                resource.generation,
            ));
        }
        transaction.commit().await.map_err(customer_sql_error)?;
        Ok(resource)
    }
}

async fn postgres_account_by_identity_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
    identity: &KeycloakIdentity,
) -> Result<Option<CustomerAccount>, CustomerResourceError> {
    let row = sqlx::query(
        r#"
        SELECT cluster_id, account_id, issuer, subject, max_projects,
               max_public_services, record_json
        FROM customer_accounts
        WHERE cluster_id = $1 AND issuer = $2 AND subject = $3
        FOR UPDATE
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(identity.issuer())
    .bind(identity.subject())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(customer_sql_error)?;
    row.map(postgres_row_to_account).transpose()
}

async fn postgres_account_by_id_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
    account_id: &CustomerAccountId,
) -> Result<Option<CustomerAccount>, CustomerResourceError> {
    let row = sqlx::query(
        r#"
        SELECT cluster_id, account_id, issuer, subject, max_projects,
               max_public_services, record_json
        FROM customer_accounts
        WHERE cluster_id = $1 AND account_id = $2
        FOR UPDATE
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(account_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(customer_sql_error)?;
    row.map(postgres_row_to_account).transpose()
}

async fn postgres_project_by_id<'e, E>(
    executor: E,
    cluster_id: &ClusterId,
    project_id: &CustomerProjectId,
) -> Result<Option<CustomerProject>, CustomerResourceError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        SELECT cluster_id, project_id, account_id, name,
               kubernetes_namespace, record_json
        FROM customer_projects
        WHERE cluster_id = $1 AND project_id = $2
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(project_id.as_str())
    .fetch_optional(executor)
    .await
    .map_err(customer_sql_error)?;
    row.map(postgres_row_to_project).transpose()
}

async fn postgres_project_by_id_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
    project_id: &CustomerProjectId,
) -> Result<Option<CustomerProject>, CustomerResourceError> {
    let row = sqlx::query(
        r#"
        SELECT cluster_id, project_id, account_id, name,
               kubernetes_namespace, record_json
        FROM customer_projects
        WHERE cluster_id = $1 AND project_id = $2
        FOR UPDATE
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(project_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(customer_sql_error)?;
    row.map(postgres_row_to_project).transpose()
}

async fn postgres_public_service_by_id<'e, E>(
    executor: E,
    cluster_id: &ClusterId,
    resource_id: &PublicServiceId,
) -> Result<Option<PublicServiceResource>, CustomerResourceError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        SELECT cluster_id, resource_id, account_id, project_id,
               name, namespace, generation, record_json
        FROM customer_public_services
        WHERE cluster_id = $1 AND resource_id = $2
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(resource_id.as_str())
    .fetch_optional(executor)
    .await
    .map_err(customer_sql_error)?;
    row.map(postgres_row_to_public_service).transpose()
}

async fn postgres_public_service_by_id_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
    resource_id: &PublicServiceId,
) -> Result<Option<PublicServiceResource>, CustomerResourceError> {
    let row = sqlx::query(
        r#"
        SELECT cluster_id, resource_id, account_id, project_id,
               name, namespace, generation, record_json
        FROM customer_public_services
        WHERE cluster_id = $1 AND resource_id = $2
        FOR UPDATE
        "#,
    )
    .bind(cluster_id.as_str())
    .bind(resource_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(customer_sql_error)?;
    row.map(postgres_row_to_public_service).transpose()
}

fn make_project(request: CreateCustomerProject) -> Result<CustomerProject, CustomerResourceError> {
    let project = CustomerProject {
        project_id: CustomerProject::generated_id(
            &request.cluster_id,
            &request.account_id,
            &request.name,
        )?,
        kubernetes_namespace: CustomerProject::generated_namespace(
            &request.cluster_id,
            &request.account_id,
            &request.name,
        )?,
        cluster_id: request.cluster_id,
        account_id: request.account_id,
        name: request.name,
        created_at: request.created_at,
    };
    project.validate()?;
    Ok(project)
}

fn make_public_service(
    request: CreatePublicService,
    project: &CustomerProject,
) -> Result<PublicServiceResource, CustomerResourceError> {
    let resource = PublicServiceResource {
        resource_id: request.resource_id,
        cluster_id: request.cluster_id,
        account_id: request.account_id,
        project_id: request.project_id,
        name: request.name,
        namespace: project.kubernetes_namespace.clone(),
        spec: request.spec,
        generation: 1,
        status: PublicServiceStatus::pending(),
        created_at: request.created_at,
        updated_at: request.created_at,
    };
    resource.validate()?;
    Ok(resource)
}

fn sqlite_row_to_account(row: SqliteRow) -> Result<CustomerAccount, CustomerResourceError> {
    let record_json: String = row.try_get("record_json").map_err(customer_sql_error)?;
    let account: CustomerAccount =
        serde_json::from_str(&record_json).map_err(customer_json_error)?;
    validate_account_columns(
        account,
        row.try_get("cluster_id").map_err(customer_sql_error)?,
        row.try_get("account_id").map_err(customer_sql_error)?,
        row.try_get("issuer").map_err(customer_sql_error)?,
        row.try_get("subject").map_err(customer_sql_error)?,
        row.try_get("max_projects").map_err(customer_sql_error)?,
        row.try_get("max_public_services")
            .map_err(customer_sql_error)?,
    )
}

fn postgres_row_to_account(row: PgRow) -> Result<CustomerAccount, CustomerResourceError> {
    let record_json: serde_json::Value = row.try_get("record_json").map_err(customer_sql_error)?;
    let account: CustomerAccount =
        serde_json::from_value(record_json).map_err(customer_json_error)?;
    validate_account_columns(
        account,
        row.try_get("cluster_id").map_err(customer_sql_error)?,
        row.try_get("account_id").map_err(customer_sql_error)?,
        row.try_get("issuer").map_err(customer_sql_error)?,
        row.try_get("subject").map_err(customer_sql_error)?,
        row.try_get("max_projects").map_err(customer_sql_error)?,
        row.try_get("max_public_services")
            .map_err(customer_sql_error)?,
    )
}

fn validate_account_columns(
    account: CustomerAccount,
    cluster_id: String,
    account_id: String,
    issuer: String,
    subject: String,
    max_projects: i64,
    max_public_services: i64,
) -> Result<CustomerAccount, CustomerResourceError> {
    account.validate()?;
    if account.cluster_id.as_str() != cluster_id
        || account.account_id.as_str() != account_id
        || account.identity.issuer() != issuer
        || account.identity.subject() != subject
        || i64::from(account.quota.max_projects) != max_projects
        || i64::from(account.quota.max_public_services) != max_public_services
    {
        return Err(corrupt_record(
            "customer account JSON does not match its durable key columns",
        ));
    }
    Ok(account)
}

fn sqlite_row_to_project(row: SqliteRow) -> Result<CustomerProject, CustomerResourceError> {
    let record_json: String = row.try_get("record_json").map_err(customer_sql_error)?;
    let project: CustomerProject =
        serde_json::from_str(&record_json).map_err(customer_json_error)?;
    validate_project_columns(
        project,
        row.try_get("cluster_id").map_err(customer_sql_error)?,
        row.try_get("project_id").map_err(customer_sql_error)?,
        row.try_get("account_id").map_err(customer_sql_error)?,
        row.try_get("name").map_err(customer_sql_error)?,
        row.try_get("kubernetes_namespace")
            .map_err(customer_sql_error)?,
    )
}

fn postgres_row_to_project(row: PgRow) -> Result<CustomerProject, CustomerResourceError> {
    let record_json: serde_json::Value = row.try_get("record_json").map_err(customer_sql_error)?;
    let project: CustomerProject =
        serde_json::from_value(record_json).map_err(customer_json_error)?;
    validate_project_columns(
        project,
        row.try_get("cluster_id").map_err(customer_sql_error)?,
        row.try_get("project_id").map_err(customer_sql_error)?,
        row.try_get("account_id").map_err(customer_sql_error)?,
        row.try_get("name").map_err(customer_sql_error)?,
        row.try_get("kubernetes_namespace")
            .map_err(customer_sql_error)?,
    )
}

fn validate_project_columns(
    project: CustomerProject,
    cluster_id: String,
    project_id: String,
    account_id: String,
    name: String,
    kubernetes_namespace: String,
) -> Result<CustomerProject, CustomerResourceError> {
    project.validate()?;
    if project.cluster_id.as_str() != cluster_id
        || project.project_id.as_str() != project_id
        || project.account_id.as_str() != account_id
        || project.name.as_str() != name
        || project.kubernetes_namespace.as_str() != kubernetes_namespace
    {
        return Err(corrupt_record(
            "customer project JSON does not match its durable key columns",
        ));
    }
    Ok(project)
}

fn sqlite_row_to_public_service(
    row: SqliteRow,
) -> Result<PublicServiceResource, CustomerResourceError> {
    let record_json: String = row.try_get("record_json").map_err(customer_sql_error)?;
    let resource: PublicServiceResource =
        serde_json::from_str(&record_json).map_err(customer_json_error)?;
    validate_public_service_columns(
        resource,
        row.try_get("cluster_id").map_err(customer_sql_error)?,
        row.try_get("resource_id").map_err(customer_sql_error)?,
        row.try_get("account_id").map_err(customer_sql_error)?,
        row.try_get("project_id").map_err(customer_sql_error)?,
        row.try_get("name").map_err(customer_sql_error)?,
        row.try_get("namespace").map_err(customer_sql_error)?,
        row.try_get("generation").map_err(customer_sql_error)?,
    )
}

fn postgres_row_to_public_service(
    row: PgRow,
) -> Result<PublicServiceResource, CustomerResourceError> {
    let record_json: serde_json::Value = row.try_get("record_json").map_err(customer_sql_error)?;
    let resource: PublicServiceResource =
        serde_json::from_value(record_json).map_err(customer_json_error)?;
    validate_public_service_columns(
        resource,
        row.try_get("cluster_id").map_err(customer_sql_error)?,
        row.try_get("resource_id").map_err(customer_sql_error)?,
        row.try_get("account_id").map_err(customer_sql_error)?,
        row.try_get("project_id").map_err(customer_sql_error)?,
        row.try_get("name").map_err(customer_sql_error)?,
        row.try_get("namespace").map_err(customer_sql_error)?,
        row.try_get("generation").map_err(customer_sql_error)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_public_service_columns(
    resource: PublicServiceResource,
    cluster_id: String,
    resource_id: String,
    account_id: String,
    project_id: String,
    name: String,
    namespace: String,
    generation: i64,
) -> Result<PublicServiceResource, CustomerResourceError> {
    resource.validate()?;
    if resource.cluster_id.as_str() != cluster_id
        || resource.resource_id.as_str() != resource_id
        || resource.account_id.as_str() != account_id
        || resource.project_id.as_str() != project_id
        || resource.name.as_str() != name
        || resource.namespace.as_str() != namespace
        || generation_to_i64(resource.generation)? != generation
    {
        return Err(corrupt_record(
            "public service JSON does not match its durable key columns",
        ));
    }
    Ok(resource)
}

fn sqlite_account_json(account: &CustomerAccount) -> Result<String, CustomerResourceError> {
    serde_json::to_string(account).map_err(customer_json_error)
}

fn sqlite_project_json(project: &CustomerProject) -> Result<String, CustomerResourceError> {
    serde_json::to_string(project).map_err(customer_json_error)
}

fn sqlite_public_service_json(
    resource: &PublicServiceResource,
) -> Result<String, CustomerResourceError> {
    serde_json::to_string(resource).map_err(customer_json_error)
}

fn postgres_account_json(
    account: &CustomerAccount,
) -> Result<serde_json::Value, CustomerResourceError> {
    serde_json::to_value(account).map_err(customer_json_error)
}

fn postgres_project_json(
    project: &CustomerProject,
) -> Result<serde_json::Value, CustomerResourceError> {
    serde_json::to_value(project).map_err(customer_json_error)
}

fn postgres_public_service_json(
    resource: &PublicServiceResource,
) -> Result<serde_json::Value, CustomerResourceError> {
    serde_json::to_value(resource).map_err(customer_json_error)
}

fn generation_to_i64(generation: u64) -> Result<i64, CustomerResourceError> {
    i64::try_from(generation).map_err(|_| CustomerResourceError::Validation {
        field: "generation",
        reason: "must not exceed the signed 64-bit database range".to_string(),
    })
}

fn page_fetch_limit(limit: usize) -> Result<i64, CustomerResourceError> {
    validate_customer_resource_page_limit(limit)?;
    i64::try_from(limit + 1)
        .map_err(|_| CustomerResourceError::Store("page limit conversion overflowed".to_string()))
}

fn account_not_found(
    cluster_id: &ClusterId,
    account_id: &CustomerAccountId,
) -> CustomerResourceError {
    CustomerResourceError::AccountNotFound {
        cluster_id: cluster_id.clone(),
        account_id: account_id.clone(),
    }
}

fn project_not_found(
    cluster_id: &ClusterId,
    project_id: &CustomerProjectId,
) -> CustomerResourceError {
    CustomerResourceError::ProjectNotFound {
        cluster_id: cluster_id.clone(),
        project_id: project_id.clone(),
    }
}

fn public_service_not_found(
    cluster_id: &ClusterId,
    resource_id: &PublicServiceId,
) -> CustomerResourceError {
    CustomerResourceError::PublicServiceNotFound {
        cluster_id: cluster_id.clone(),
        resource_id: resource_id.clone(),
    }
}

fn duplicate_name(kind: CustomerResourceKind, name: KubernetesName) -> CustomerResourceError {
    CustomerResourceError::DuplicateName { kind, name }
}

fn generation_conflict(
    resource_id: &PublicServiceId,
    expected: u64,
    actual: u64,
) -> CustomerResourceError {
    CustomerResourceError::GenerationConflict {
        resource_id: resource_id.clone(),
        expected,
        actual,
    }
}

fn ensure_project_owner(
    project: &CustomerProject,
    account_id: &CustomerAccountId,
) -> Result<(), CustomerResourceError> {
    if &project.account_id != account_id {
        return Err(CustomerResourceError::OwnershipMismatch {
            kind: CustomerResourceKind::Project,
            resource_id: project.project_id.to_string(),
            requested_account_id: account_id.clone(),
        });
    }
    Ok(())
}

fn ensure_public_service_owner(
    resource: &PublicServiceResource,
    account_id: &CustomerAccountId,
    project_id: &CustomerProjectId,
) -> Result<(), CustomerResourceError> {
    if &resource.account_id != account_id || &resource.project_id != project_id {
        return Err(CustomerResourceError::OwnershipMismatch {
            kind: CustomerResourceKind::PublicService,
            resource_id: resource.resource_id.to_string(),
            requested_account_id: account_id.clone(),
        });
    }
    Ok(())
}

fn account_insert_error(error: sqlx::Error, account: &CustomerAccount) -> CustomerResourceError {
    let (constraint, message) = database_error_parts(&error);
    if constraint == "customer_accounts_pkey"
        || message.contains("customer_accounts.cluster_id, customer_accounts.account_id")
    {
        return CustomerResourceError::IdentifierCollision {
            kind: CustomerResourceKind::Account,
            resource_id: account.account_id.to_string(),
        };
    }
    customer_sql_error(error)
}

fn project_insert_error(error: sqlx::Error, project: &CustomerProject) -> CustomerResourceError {
    let (constraint, message) = database_error_parts(&error);
    if constraint == "customer_projects_owner_name_unique"
        || message.contains(
            "customer_projects.cluster_id, customer_projects.account_id, customer_projects.name",
        )
    {
        return duplicate_name(CustomerResourceKind::Project, project.name.clone());
    }
    if constraint == "customer_projects_pkey"
        || constraint == "customer_projects_namespace_unique"
        || message.contains("customer_projects.cluster_id, customer_projects.project_id")
        || message.contains("customer_projects.cluster_id, customer_projects.kubernetes_namespace")
    {
        return CustomerResourceError::IdentifierCollision {
            kind: CustomerResourceKind::Project,
            resource_id: project.project_id.to_string(),
        };
    }
    customer_sql_error(error)
}

fn public_service_insert_error(
    error: sqlx::Error,
    resource: &PublicServiceResource,
) -> CustomerResourceError {
    let (constraint, message) = database_error_parts(&error);
    if constraint == "customer_public_services_project_name_unique"
        || message.contains(
            "customer_public_services.cluster_id, customer_public_services.project_id, customer_public_services.name",
        )
    {
        return duplicate_name(
            CustomerResourceKind::PublicService,
            resource.name.clone(),
        );
    }
    if constraint == "customer_public_services_pkey"
        || message
            .contains("customer_public_services.cluster_id, customer_public_services.resource_id")
    {
        return CustomerResourceError::IdentifierCollision {
            kind: CustomerResourceKind::PublicService,
            resource_id: resource.resource_id.to_string(),
        };
    }
    customer_sql_error(error)
}

fn database_error_parts(error: &sqlx::Error) -> (&str, &str) {
    if let sqlx::Error::Database(database_error) = error {
        (
            database_error.constraint().unwrap_or_default(),
            database_error.message(),
        )
    } else {
        ("", "")
    }
}

fn corrupt_record(message: impl Into<String>) -> CustomerResourceError {
    CustomerResourceError::Store(message.into())
}

fn customer_sql_error(error: sqlx::Error) -> CustomerResourceError {
    CustomerResourceError::Store(error.to_string())
}

fn customer_json_error(error: serde_json::Error) -> CustomerResourceError {
    CustomerResourceError::Store(error.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration as StdDuration;

    use chrono::{Duration, Utc};
    use ipars_control_plane::customer_resources::{
        CustomerQuota, PublicServiceAddress, PublicServicePhase, PublicServiceProtocol,
        PublicServiceSpec, PublicServiceTrafficMode, MAX_CUSTOMER_RESOURCE_PAGE_SIZE,
    };
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    fn identity(issuer: &str, subject: &str) -> KeycloakIdentity {
        KeycloakIdentity::new(issuer, subject).expect("test identity must be valid")
    }

    fn account_request(
        cluster_id: &ClusterId,
        identity: KeycloakIdentity,
        quota: CustomerQuota,
    ) -> EnsurePersonalAccount {
        EnsurePersonalAccount {
            cluster_id: cluster_id.clone(),
            identity,
            quota,
            created_at: Utc::now(),
        }
    }

    fn project_request(account: &CustomerAccount, name: &str) -> CreateCustomerProject {
        CreateCustomerProject {
            cluster_id: account.cluster_id.clone(),
            account_id: account.account_id.clone(),
            name: KubernetesName::parse(name).expect("test project name must be valid"),
            created_at: Utc::now(),
        }
    }

    fn public_service_request(
        account: &CustomerAccount,
        project: &CustomerProject,
        name: &str,
    ) -> CreatePublicService {
        CreatePublicService {
            cluster_id: account.cluster_id.clone(),
            resource_id: test_public_service_id(name),
            account_id: account.account_id.clone(),
            project_id: project.project_id.clone(),
            name: KubernetesName::parse(name).expect("test resource name must be valid"),
            spec: PublicServiceSpec {
                traffic_mode: PublicServiceTrafficMode::Direct,
                protocol: PublicServiceProtocol::Udp,
                public_port: 7882,
                backend_service: KubernetesName::parse("livekit")
                    .expect("test backend name must be valid"),
                backend_port: 7882,
                ingress_replicas: 2,
            },
            created_at: Utc::now(),
        }
    }

    fn test_public_service_id(name: &str) -> PublicServiceId {
        let mut entropy = [0_u8; 16];
        for (target, source) in entropy.iter_mut().zip(name.bytes()) {
            *target = source;
        }
        PublicServiceId::from_entropy(entropy)
    }

    fn temp_sqlite_url(name: &str) -> (String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ipars-customer-resources-{name}-{}-{}.sqlite",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        (format!("sqlite://{}?mode=rwc", path.display()), path)
    }

    async fn sqlite_store(
        database_url: &str,
    ) -> Result<SqliteControlPlaneStore, Box<dyn std::error::Error>> {
        let options =
            SqliteConnectOptions::from_str(database_url)?.busy_timeout(StdDuration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        Ok(SqliteControlPlaneStore::from_pool(pool).await?)
    }

    #[tokio::test]
    async fn sqlite_customer_resource_contract_survives_reopen(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("contract");
        let cluster_id = ClusterId::from_string("cluster-a");
        let store = sqlite_store(&database_url).await?;
        migrate_sqlite_customer_resources(&store.pool).await?;
        let owner = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id-a.example/realms/customers", "subject-a"),
                CustomerQuota::new(2, 1)?,
            ))
            .await?;
        let other_issuer = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id-b.example/realms/customers", "subject-a"),
                CustomerQuota::default(),
            ))
            .await?;
        assert_ne!(owner.account_id, other_issuer.account_id);

        let project = store
            .create_customer_project(project_request(&owner, "media"))
            .await?;
        assert!(matches!(
            store
                .create_customer_project(project_request(&owner, "media"))
                .await,
            Err(CustomerResourceError::DuplicateName {
                kind: CustomerResourceKind::Project,
                ..
            })
        ));
        let second_project = store
            .create_customer_project(project_request(&owner, "games"))
            .await?;
        assert!(matches!(
            store
                .create_customer_project(project_request(&owner, "third"))
                .await,
            Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::Project,
                limit: 2
            })
        ));

        let resource = store
            .create_public_service(public_service_request(&owner, &project, "livekit"))
            .await?;
        assert!(matches!(
            store
                .create_public_service(public_service_request(&owner, &project, "livekit"))
                .await,
            Err(CustomerResourceError::DuplicateName {
                kind: CustomerResourceKind::PublicService,
                ..
            })
        ));
        assert!(matches!(
            store
                .create_public_service(public_service_request(&owner, &second_project, "agones"))
                .await,
            Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: 1
            })
        ));
        assert!(matches!(
            store
                .get_public_service(
                    &cluster_id,
                    &other_issuer.account_id,
                    &project.project_id,
                    &resource.resource_id
                )
                .await,
            Err(CustomerResourceError::OwnershipMismatch { .. })
        ));

        let ready = PublicServiceStatus {
            phase: PublicServicePhase::Ready,
            public_addresses: vec![PublicServiceAddress::new(
                "203.0.113.10",
                resource.spec.public_port,
            )?],
            message: None,
            observed_generation: resource.generation,
            observed_at: Some(Utc::now() + Duration::seconds(1)),
        };
        assert!(matches!(
            store
                .update_public_service_status(&cluster_id, &resource.resource_id, 0, ready.clone())
                .await,
            Err(CustomerResourceError::GenerationConflict {
                expected: 0,
                actual: 1,
                ..
            })
        ));
        store
            .update_public_service_status(
                &cluster_id,
                &resource.resource_id,
                resource.generation,
                ready,
            )
            .await?;
        drop(store);

        let reopened = sqlite_store(&database_url).await?;
        assert_eq!(
            reopened
                .get_personal_account(&cluster_id, &owner.identity)
                .await?,
            Some(owner.clone())
        );
        assert_eq!(
            reopened
                .list_desired_public_services(&cluster_id, None, MAX_CUSTOMER_RESOURCE_PAGE_SIZE,)
                .await?
                .public_services
                .len(),
            1
        );
        assert!(
            reopened
                .delete_customer_project(&cluster_id, &owner.account_id, &project.project_id)
                .await?
        );
        assert!(reopened
            .list_desired_public_services(&cluster_id, None, MAX_CUSTOMER_RESOURCE_PAGE_SIZE)
            .await?
            .public_services
            .is_empty());
        assert!(
            reopened
                .delete_customer_account(&cluster_id, &owner.account_id)
                .await?
        );
        assert!(reopened
            .get_customer_account(&cluster_id, &owner.account_id)
            .await?
            .is_none());
        drop(reopened);

        let _ = std::fs::remove_file(&database_path);
        let _ = std::fs::remove_file(format!("{}-shm", database_path.display()));
        let _ = std::fs::remove_file(format!("{}-wal", database_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_project_quota_is_atomic_across_store_instances(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("atomic-quota");
        let cluster_id = ClusterId::from_string("cluster-a");
        let store_a = sqlite_store(&database_url).await?;
        let store_b = sqlite_store(&database_url).await?;
        let account = store_a
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "subject-a"),
                CustomerQuota::new(1, 1)?,
            ))
            .await?;

        let first_request = project_request(&account, "first");
        let second_request = project_request(&account, "second");
        let (first, second) = tokio::join!(
            store_a.create_customer_project(first_request),
            store_b.create_customer_project(second_request)
        );
        let success_count = usize::from(first.is_ok()) + usize::from(second.is_ok());
        assert_eq!(success_count, 1);
        let error = first
            .err()
            .or_else(|| second.err())
            .ok_or("one concurrent project creation should have failed")?;
        assert!(matches!(
            error,
            CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::Project,
                limit: 1
            }
        ));
        assert_eq!(
            store_a
                .list_customer_projects(
                    &cluster_id,
                    &account.account_id,
                    None,
                    MAX_CUSTOMER_RESOURCE_PAGE_SIZE,
                )
                .await?
                .projects
                .len(),
            1
        );
        drop(store_a);
        drop(store_b);

        let _ = std::fs::remove_file(&database_path);
        let _ = std::fs::remove_file(format!("{}-shm", database_path.display()));
        let _ = std::fs::remove_file(format!("{}-wal", database_path.display()));
        Ok(())
    }

    #[tokio::test]
    async fn postgres_customer_resource_contract_when_configured(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Ok(database_url) = std::env::var("IPARS_TEST_POSTGRES_URL") else {
            return Ok(());
        };
        let cluster_id = ClusterId::from_string(format!(
            "customer-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = PostgresControlPlaneStore::connect(&database_url).await?;
        let account = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "subject-a"),
                CustomerQuota::new(1, 1)?,
            ))
            .await?;
        let project = store
            .create_customer_project(project_request(&account, "media"))
            .await?;
        assert!(matches!(
            store
                .create_customer_project(project_request(&account, "other"))
                .await,
            Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::Project,
                limit: 1
            })
        ));
        let resource = store
            .create_public_service(public_service_request(&account, &project, "livekit"))
            .await?;
        let ready = PublicServiceStatus {
            phase: PublicServicePhase::Ready,
            public_addresses: vec![PublicServiceAddress::new(
                "203.0.113.10",
                resource.spec.public_port,
            )?],
            message: None,
            observed_generation: resource.generation,
            observed_at: Some(Utc::now() + Duration::seconds(1)),
        };
        assert!(matches!(
            store
                .update_public_service_status(&cluster_id, &resource.resource_id, 0, ready.clone())
                .await,
            Err(CustomerResourceError::GenerationConflict { .. })
        ));
        store
            .update_public_service_status(
                &cluster_id,
                &resource.resource_id,
                resource.generation,
                ready,
            )
            .await?;

        let reopened = PostgresControlPlaneStore::connect(&database_url).await?;
        assert_eq!(
            reopened
                .list_desired_public_services(&cluster_id, None, MAX_CUSTOMER_RESOURCE_PAGE_SIZE,)
                .await?
                .public_services
                .len(),
            1
        );
        assert!(
            reopened
                .delete_customer_account(&cluster_id, &account.account_id)
                .await?
        );
        assert!(reopened
            .list_desired_public_services(&cluster_id, None, MAX_CUSTOMER_RESOURCE_PAGE_SIZE)
            .await?
            .public_services
            .is_empty());
        Ok(())
    }
}
