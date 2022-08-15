import java
private import semmle.code.java.dataflow.ExternalFlow

private class SpringProjectsSpringDataJpaSummaryModelCustom extends SummaryModelCsv {
  override predicate row(string row) {
    row = [
      "org.springframework.data.repository;CrudRepository;true;save;;;Argument[0];ReturnValue;value;manual"
    ]
  }
}

