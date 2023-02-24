package org.rscarela.security.pendragon.bootstrap.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Named
public class URIConfigurations {

    private final Map<HttpMethod, String[]> mappedPermittedURIs;
    private final Map<HttpMethod, String[]> mappedDeniedURIs;

    private final String signUpURI;
    private final String signInURI;

    @Inject
    public URIConfigurations(
            @Value("${pendragon.filter.uri.signUp}") String signUpURI,
            @Value("${pendragon.filter.uri.signIn}") String signInURI,
            @Value("${pendragon.filter.uri.permit:[]}") List<String> permittedURIs,
            @Value("${pendragon.filter.uri.deny:[]}") List<String> deniedURIs) {
        this.signUpURI = signUpURI;
        this.signInURI = signInURI;
        this.mappedPermittedURIs = new HashMap<>();
        this.mappedDeniedURIs = new HashMap<>();

        permittedURIs.add(signUpURI);
        permittedURIs.add(signInURI);

        mapPermittedURIs(permittedURIs);
        mapDeniedURIs(deniedURIs);
    }

    public Map<HttpMethod, String[]> getPermittedURIs() {
        return Collections.unmodifiableMap(mappedPermittedURIs);
    }

    public Map<HttpMethod, String[]> getDeniedURIs() {
        return Collections.unmodifiableMap(mappedDeniedURIs);
    }

    public String getSignInPath() {
        return signInURI.split(" ")[1];
    }

    private void mapPermittedURIs(List<String> permittedURIs) {
        for (HttpMethod method : HttpMethod.values()) {
            List<String> mappedURIs = new ArrayList<>();

            mappedURIs.addAll(extract(method, permittedURIs));

            String[] result = new String[mappedURIs.size()];
            mappedPermittedURIs.put(method, mappedURIs.toArray(result));
        }
    }

    private void mapDeniedURIs(List<String> deniedURIs) {
        for (HttpMethod method : HttpMethod.values()) {
            List<String> mappedURIs = new ArrayList<>();

            mappedURIs.addAll(extract(method, deniedURIs));

            String[] result = new String[mappedURIs.size()];
            mappedDeniedURIs.put(method, mappedURIs.toArray(result));
        }
    }

    private List<String> extract(HttpMethod method, List<String> URIs) {
        if (URIs == null || URIs.isEmpty()) return Collections.emptyList();

        return URIs.stream()
                .filter(uri ->
                    uri.contains(" ") &&
                    uri.split(" ")[0].equals(method.toString()))
                .map(uri -> uri.split(" ")[1])
                .collect(Collectors.toList());
    }

}
