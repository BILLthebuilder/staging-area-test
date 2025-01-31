package rafikibora.model.terminal;



import rafikibora.model.account.Account;
import rafikibora.model.transactions.Transaction;
import rafikibora.model.users.User;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "terminals")
public class Terminal implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name="terminal_id")
    private int id;

    @Column(name = "tid",nullable = false, unique = true, columnDefinition = "VARCHAR(16)")
    private String tid;

    @Column(name = "serial_no",nullable = false, unique = true, columnDefinition = "VARCHAR(28)")
    private String serialNo;

    @Column(name = "model_type",nullable = false, columnDefinition = "VARCHAR(10)")
    private String modelType;

    @Column(name = "status", columnDefinition = "TINYINT(1) DEFAULT 0")
    private boolean status;

    @JsonBackReference(value = "mid_t")
    @ManyToOne
    @JoinColumn(name="mid", referencedColumnName = "mid")
    private User merchant;

    @JsonBackReference(value = "created_by_t")
    @ManyToOne
    @JoinColumn(name="created_by", nullable = false, referencedColumnName = "user_id")
    private User terminalMaker;

    @JsonBackReference(value = "approved_by_t")
    @ManyToOne
    @JoinColumn(name="approved_by", referencedColumnName = "user_id")
    private User terminalChecker;

    @Column(name = "is_deleted", columnDefinition = "TINYINT(1) DEFAULT 0")
    private boolean isDeleted;

    @Column(name = "date_added", updatable=false, columnDefinition = "DATETIME DEFAULT CURRENT_TIMESTAMP")
    @Temporal(value = TemporalType.TIMESTAMP)
    private Date dateCreated;

    @Column(name = "date_updated", columnDefinition = "DATETIME ON UPDATE CURRENT_TIMESTAMP")
    @Temporal(value = TemporalType.TIMESTAMP)
    private Date dateUpdated;

    @JsonBackReference(value = "user_id_t")
    @ManyToOne
    @JoinColumn(name="user_id", nullable = false, referencedColumnName = "user_id")
    private User user;


    @OneToMany(mappedBy="terminal",cascade={CascadeType.PERSIST, CascadeType.MERGE}, fetch = FetchType.LAZY)
    @JsonManagedReference(value = "tid_t")
    private List<Transaction> transactions = new ArrayList<Transaction>();

}
