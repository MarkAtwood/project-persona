use std::pin::Pin;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use persona_attestors::Attestor;
use persona_core::{SvidSigner, TrustBundleStore};

use crate::workload::{
    spiffe_workload_api_server::SpiffeWorkloadApi, JwtBundlesRequest, JwtBundlesResponse,
    JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest, ValidateJwtsvidResponse,
    WitBundlesRequest, WitBundlesResponse, WitsvidRequest, WitsvidResponse, X509BundlesRequest,
    X509BundlesResponse, X509svidRequest, X509svidResponse,
};

pub struct WorkloadApiService {
    pub signer: Arc<SvidSigner>,
    pub bundles: Arc<TrustBundleStore>,
    pub attestors: Vec<Arc<dyn Attestor>>,
}

impl WorkloadApiService {
    pub fn new(
        signer: Arc<SvidSigner>,
        bundles: Arc<TrustBundleStore>,
        attestors: Vec<Arc<dyn Attestor>>,
    ) -> Self {
        Self {
            signer,
            bundles,
            attestors,
        }
    }
}

type BoxStream<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl SpiffeWorkloadApi for WorkloadApiService {
    type FetchX509SVIDStream = BoxStream<X509svidResponse>;
    type FetchX509BundlesStream = BoxStream<X509BundlesResponse>;
    type FetchJWTBundlesStream = BoxStream<JwtBundlesResponse>;
    type FetchWITSVIDStream = BoxStream<WitsvidResponse>;
    type FetchWITBundlesStream = BoxStream<WitBundlesResponse>;

    // persona-4qm: X.509-SVID issuance not yet implemented
    async fn fetch_x509svid(
        &self,
        _req: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        Err(Status::unimplemented(
            "X.509-SVID issuance not yet implemented",
        ))
    }

    // persona-rbu: Return X.509 bundles for all active trust domains
    async fn fetch_x509_bundles(
        &self,
        _req: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        let bundles = self
            .bundles
            .snapshot()
            .into_iter()
            .map(|b| {
                // Concatenate all DER-encoded CA certs for this trust domain.
                let der_blob: Vec<u8> = b.x509_authorities.into_iter().flatten().collect();
                (b.trust_domain.to_string(), der_blob)
            })
            .collect();
        let response = X509BundlesResponse {
            crl: vec![],
            bundles,
        };
        let stream = tokio_stream::once(Ok(response));
        Ok(Response::new(Box::pin(stream)))
    }

    // persona-rbu: Return JWKS bundles for all active trust domains
    async fn fetch_jwt_bundles(
        &self,
        _req: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        let bundles = self
            .bundles
            .snapshot()
            .into_iter()
            .map(|b| {
                let jwks_bytes = serde_json::to_vec(&b.jwt_authorities).unwrap_or_default();
                (b.trust_domain.to_string(), jwks_bytes)
            })
            .collect();
        let response = JwtBundlesResponse { bundles };
        let stream = tokio_stream::once(Ok(response));
        Ok(Response::new(Box::pin(stream)))
    }

    // Stub — persona-rrv will implement JWT-SVID issuance
    async fn fetch_jwtsvid(
        &self,
        _req: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        Err(Status::unimplemented("FetchJWTSVID not yet implemented"))
    }

    async fn validate_jwtsvid(
        &self,
        _req: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        Err(Status::unimplemented("ValidateJWTSVID not yet implemented"))
    }

    async fn fetch_witsvid(
        &self,
        _req: Request<WitsvidRequest>,
    ) -> Result<Response<Self::FetchWITSVIDStream>, Status> {
        Err(Status::unimplemented("FetchWITSVID not yet implemented"))
    }

    async fn fetch_wit_bundles(
        &self,
        _req: Request<WitBundlesRequest>,
    ) -> Result<Response<Self::FetchWITBundlesStream>, Status> {
        Err(Status::unimplemented("FetchWITBundles not yet implemented"))
    }
}
