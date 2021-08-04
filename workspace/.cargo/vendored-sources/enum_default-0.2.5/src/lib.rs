extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;

/// EnumDefault provides a std::Default implementation for enums
/// by using the first item as the return of <enum>::default()
#[proc_macro_derive(EnumDefault, attributes(default))]
pub fn enum_default_derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).unwrap();

    match ast.data {
        syn::Data::Enum(data) => {
            if data.variants.is_empty() {
                return TokenStream::default();
            }
            let name = ast.ident;

            // check if they have the "#[default]" attribute
            let iter = data.variants.iter();
            for variant in iter {
                for attr in &variant.attrs {
                    if attr.path.is_ident("default") {
                        return impl_enum_default(&name, &variant.ident);
                    }
                }
            }

            // fallback to the first item
            let first_variant = data.variants.first().unwrap();
            let variant = &first_variant.ident;
            impl_enum_default(&name, variant)
        }
        _ => TokenStream::default(),
    }
}

fn impl_enum_default(name: &syn::Ident, variant: &syn::Ident) -> TokenStream {
    let result = quote! {
      impl Default for #name {
        fn default() -> #name {
          #name::#variant
        }
      }
    };
    result.into()
}
